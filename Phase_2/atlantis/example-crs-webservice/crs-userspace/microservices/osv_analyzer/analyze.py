import logging
import threading
from pathlib import Path
import os
import subprocess
import shutil
import shlex
import asyncio
import concurrent.futures
from typing import Any, Coroutine
import time

from libatlantis.protobuf import CPConfig, OSVAnalyzerResult, BuildRequestResponse, FileOpsResponse, CONFIG_GEN, SUCCESS, FAILURE
from libatlantis.constants import LARGE_DATA_DIR, CRS_SCRATCH_DIR
from libCRS.util import run_cmd

try:
    from libAgents.utils import Project, get_model_by_weights, copy_dir
    from libAgents.agents import analyze_corpus_relevance, fast_analyze_corpus_relevance
    DISABLE_AGENTS = False
except:
    # yikes this is bad
    DISABLE_AGENTS = True

from . import config


logger = logging.getLogger(__name__)


def _run(cmd, cwd=None):
    cmd = list(map(str, cmd))
    cwd = os.getcwd() if cwd is None else cwd
    logger.info(f'{" ".join(cmd)}')
    return subprocess.run(cmd, check=False, capture_output=True, cwd=str(cwd))

def rsync(src: Path, dst: Path, delete: bool=False):
    if src.is_dir():
        src = f"{src}/."
    if delete:
        _run(["rsync", "-a", "--delete", src, dst])
    else:
        _run(["rsync", "-a", src, dst])

def get_categories_from_directory(directory):
    """
    Get all category names from the categories directory.
    
    Args:
        directory: Path to the categories directory
    
    Returns:
        Set of category names
    """
    categories = set()
    
    dir_path = Path(directory)
    if not dir_path.exists():
        logger.warning(f"Directory '{directory}' does not exist")
        return categories
    
    for item_path in dir_path.iterdir():
        if item_path.is_dir():  # Only get directories (categories)
            categories.add(item_path.name)
    
    return categories

class OSVAnalyzer:
    """
    Matches a given CP against known OSS-Fuzz categories,
    and collects their dicts and corpus for fuzzing.
    The matching algorithm is based on filename Jaccard similarity.
    """
    def __init__(self):
        self.cp_config = None
        self.categories_dir = None
        self.matched_categories = None
        self.oss_dicts = None
        self.oss_corpus = None
        self.cp_mount_path = None
        self.build_request_response = None
        self.project_bundle = None
        self.received_file_ops = False
        self.categories_dir = config.DATA_DIR / "fuzz-corpus" / "categories"
        self.lock = threading.Lock()
        self.main_lock = threading.Lock()
        self.available_categories = self.get_all_categories()

        self.loop = None
        self.thread = None
        self._shutdown = False
        self.start()

    # async stuff
    def start(self):
        """Start the background event loop"""
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
            
        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()
        
        # Wait for loop to be ready
        while self.loop is None:
            threading.Event().wait(0.01)
            
    def run_coroutine(self, coro: Coroutine) -> Any:
        """Run a coroutine in the background loop and return result"""
        if self.loop is None:
            raise RuntimeError("AsyncRunner not started")
        
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result()  # Blocks until complete
    
    def shutdown(self):
        """Shutdown the background loop"""
        if self.loop and not self._shutdown:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join()
            self._shutdown = True

    def get_all_categories(self) -> list[str]:
        """Get all available categories from the categories directory"""
        categories = get_categories_from_directory(self.categories_dir)
        return list(categories)

    def process_cp_config(self, cp_config: CPConfig):
        with self.main_lock:
            self.cp_config = cp_config

            if len(self.available_categories) > 0 and not DISABLE_AGENTS:
                models = ["gemini-2.5-pro", "o3"]
                results = {} # model -> list[str]

                async def run_analysis():
                    coroutines = []
                    for model in models:
                        coro = fast_analyze_corpus_relevance(
                            model,
                            cp_config.cp_name,
                            self.available_categories,
                        )
                        coroutines.append(coro)

                    with self.lock:
                        if self.matched_categories is not None:
                            return

                    all_results = await asyncio.gather(*coroutines)
                    all_category_names = set()
                    for i, (_, corpus_matches) in enumerate(all_results):
                        it_category_names = []
                        for _harness, relevant_categories in corpus_matches.items():
                            it_category_names.extend(relevant_categories)
                        all_category_names.update(it_category_names)
                        results[models[i]] = it_category_names

                    with self.lock:
                        if self.matched_categories is None:
                            self.matched_categories = list(all_category_names)
                            logger.info(f"Models to results: {results}")
                            logger.info(f"Categories matched in fast path: {self.matched_categories}")

                try:
                    self.run_coroutine(asyncio.wait_for(run_analysis(), timeout=600))
                    # asyncio.run(asyncio.wait_for(run_analysis(), timeout=600)) # 10 minutes
                except asyncio.TimeoutError:
                    logger.warning("Fast category corpus analysis failed, timed out")
                except:
                    logger.warning("Fast category corpus analysis failed")

            return []

    def process_harness_builder_result(self, build_request_response: BuildRequestResponse):
        with self.main_lock:
            if build_request_response.mode != CONFIG_GEN:
                return []
            if build_request_response.status == FAILURE:
                return self.get_result()
            self.build_request_response = build_request_response
            self.cp_mount_path = build_request_response.cp_mount_path

            return self.run()

    def process_file_ops_response(self, input_message: FileOpsResponse):
        with self.main_lock:
            if input_message.node_idx != 0:
                logger.info("This is not the fileops response from node 0, skipping")
                return []

            self.received_file_ops = True
            return self.run()

    # NOTE copied from deepgen service worker.py
    def __get_post_build_project_bundle(self):
        if self.project_bundle:
            return self.project_bundle

        oss_fuzz_home = Path(self.cp_config.oss_fuzz_path)
        project_name = self.cp_config.cp_name
        original_project_path = f"{oss_fuzz_home}/projects/{project_name}"

        atlantis_path = Path(oss_fuzz_home) / "atlantis"
        local_atlantis_path = CRS_SCRATCH_DIR / "osv-analyzer" / "atlantis"
        workdir = CRS_SCRATCH_DIR / "osv-analyzer" / "workdir"
        workdir.mkdir(exist_ok=True, parents=True)

        # copy the whole
        if os.path.exists(local_atlantis_path):
            shutil.rmtree(local_atlantis_path)
        cmd = ['rsync', '-av', str(atlantis_path)+'/', str(local_atlantis_path)+'/']
        logger.info(f"Copy atlantis to local node {shlex.join(cmd)}")
        run_cmd(cmd)


        cp_mount_path = self.cp_mount_path
        if cp_mount_path.startswith('/'):
            cp_mount_path = cp_mount_path.lstrip('/')
        post_build_repo_path = os.path.join(local_atlantis_path, cp_mount_path)
        post_build_project_path = os.path.join(local_atlantis_path, "src")

        # copy the .aixcc stuff
        cmd = ['rsync', '-avh', '--ignore-existing', str(original_project_path)+'/', str(post_build_project_path)+'/']
        logger.info(f"Copy .aixcc to local node {shlex.join(cmd)}")
        run_cmd(cmd)
        
        logger.info(f"Project name: {project_name}")
        logger.info(f"Post build project path: {post_build_project_path}")
        logger.info(f"Post build repo path: {post_build_repo_path}")

        self.project_bundle = Project(
            project_name=project_name,
            project_path=post_build_project_path,
            repo_path=post_build_repo_path,
        ).prepare_project_bundle(workdir)

        return self.project_bundle


    def match_all_repos_agent_call(self):
        if len(self.available_categories) == 0:
            logger.warning("No available categories from large_data, skipping agent call")
            return []

        if DISABLE_AGENTS:
            return []

        bundle = self.__get_post_build_project_bundle()
        logger.info(f"Project bundle from config gen {bundle}")

        category_names = set()

        # _format_analysis, corpus_matches = asyncio.run(analyze_corpus_relevance(
        _format_analysis, corpus_matches = self.run_coroutine(analyze_corpus_relevance(
            model="gemini-2.5-pro",
            project_bundle=bundle,
            available_categories=self.available_categories,
            timeout=750,
            use_backup_corpus_matcher = True, # make the second stage fast
        ))

        if corpus_matches:
            for harness, relevant_categories in corpus_matches.items():
                if relevant_categories:
                    category_names.update(relevant_categories)

        if len(category_names) > 0:
            with self.lock:
                self.matched_categories = list(category_names)
                logger.info(f"Categories matched in agent call: {self.matched_categories}")
        else:
            logger.warning("No matching results available, using fallback")

        return self.matched_categories

    def get_dict_paths(self, category_name: str) -> list[Path]:
        """Get all dictionary files for a given category"""
        dict_folder = self.categories_dir / category_name / "dictionaries"
        if not dict_folder.is_dir():
            return []

        return [
            item
            for item in dict_folder.iterdir()
            if item.is_file()
        ]

    def get_corpus_path(self, category_name: str) -> list[Path]:
        """Get corpus file for a given category"""
        corpus_folder = self.categories_dir / category_name / "corpus"
        if not corpus_folder.is_dir():
            return []

        # Look for .tar.zst files in the corpus directory
        corpus_files = []
        for item in corpus_folder.iterdir():
            if item.is_file() and item.name.endswith('.tar.zst'):
                corpus_files.append(item)

        return corpus_files

    def get_oss_dicts(self) -> list[Path]:
        """Return a list of OSS dict file paths"""
        if self.oss_dicts is not None:
            return self.oss_dicts

        if not self.matched_categories:
            return []

        res = [self.get_dict_paths(category_name) for category_name in self.matched_categories]
        oss_dicts = list(set(item for sublist in res for item in sublist))

        shared_oss_dicts_dir = LARGE_DATA_DIR / "osv_analyzer/dicts"
        shared_oss_dicts_dir.mkdir(parents=True, exist_ok=True)

        shared_oss_dicts = []
        for oss_dict in oss_dicts:
            rsync(oss_dict, shared_oss_dicts_dir / oss_dict.name)
            shared_oss_dicts.append(shared_oss_dicts_dir / oss_dict.name)

        logger.info(f"Found OSS dicts: {oss_dicts}")
        return shared_oss_dicts

    def get_oss_corpus(self) -> list[Path]:
        """Return a list of OSS corpus zip file paths"""
        if self.oss_corpus is not None:
            return self.oss_corpus

        if not self.matched_categories:
            return []

        res = [self.get_corpus_path(category_name) for category_name in self.matched_categories]
        oss_corpus = list(set(item for sublist in res if sublist for item in sublist))

        shared_oss_corpus_dir = LARGE_DATA_DIR / "osv_analyzer/corpus"
        shared_oss_corpus_dir.mkdir(parents=True, exist_ok=True)

        shared_oss_corpus = []
        for oss_corpus in oss_corpus:
            rsync(oss_corpus, shared_oss_corpus_dir / oss_corpus.name)
            shared_oss_corpus.append(shared_oss_corpus_dir / oss_corpus.name)

        logger.info(f"Found OSS corpus: {shared_oss_corpus}")
        return shared_oss_corpus

    def get_result(self):
        result = OSVAnalyzerResult(
            corpus_files = [],
            dictionary_files = [],
            project_names = [],
            cp_src_path = self.cp_config.cp_src_path,
        )
        try:
            self.oss_dicts = self.get_oss_dicts()
            self.oss_corpus = self.get_oss_corpus()
            result = OSVAnalyzerResult(
                corpus_files = [str(p.resolve()) for p in self.oss_corpus],
                dictionary_files = [str(p.resolve()) for p in self.oss_dicts],
                project_names = self.matched_categories,  # Using categories instead of project names
                cp_src_path = self.cp_config.cp_src_path,
            )
        except:
            logger.warning("Failed to get OSS dicts or corpus, returning empty result")
        return [result]
    
    def run(self):
        if self.build_request_response is None:
            return []

        if not self.received_file_ops:
            return []

        try:
            self.matched_categories = self.match_all_repos_agent_call()
        except:
            logger.warning("Failed to match categories using agent call, using fallback")
        return self.get_result()


