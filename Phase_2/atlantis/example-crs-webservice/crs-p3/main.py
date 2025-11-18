import asyncio
import gc
import os
from pathlib import Path
from typing import cast

import torch
from datasets import Dataset  # pyright: ignore[reportMissingTypeStubs]
from fastapi import Depends, FastAPI
from huggingface_hub import login
from peft import LoraConfig, TaskType, get_peft_model
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from transformers.data.data_collator import DataCollatorForLanguageModeling
from transformers.modeling_utils import PreTrainedModel
from transformers.tokenization_utils import PreTrainedTokenizer
from transformers.trainer import Trainer
from transformers.trainer_callback import EarlyStoppingCallback
from transformers.training_args import TrainingArguments

app = FastAPI()

login(os.getenv("HF_TOKEN", None))

if os.getenv("MODEL", None) is None:
    raise ValueError("Please set the MODEL environment variable to the base model ID.")

BASE_MODEL_ID = f"models/{os.getenv('MODEL', None)}"


class AdaptationRequest(BaseModel):
    id: str
    text: str
    block_size: int = 256
    learning_rate: float = 2e-5
    per_device_train_batch_size: int = 8
    num_train_epochs: int = 32
    lora_rank: int = 8
    lora_alpha: int = 32
    lora_dropout: float = 0.1


MODEL = cast(
    PreTrainedModel,
    AutoModelForCausalLM.from_pretrained(  # pyright: ignore[reportUnknownMemberType]
        BASE_MODEL_ID,
        device_map="auto",
        torch_dtype="auto",
    ),
)
TOKENIZER = cast(
    PreTrainedTokenizer,
    AutoTokenizer.from_pretrained(  # pyright: ignore[reportUnknownMemberType]
        BASE_MODEL_ID
    ),
)

DATA_COLLATOR = DataCollatorForLanguageModeling(tokenizer=TOKENIZER, mlm=False)
ADAPTERS_DIRECTORY = Path(__file__).parent / "adapters"

if TOKENIZER.pad_token_id is None:  # type: ignore
    TOKENIZER.pad_token_id = TOKENIZER.eos_token_id  # type: ignore


@app.post("/adapt")
async def adapt(
    request: AdaptationRequest, _=Depends(lambda: _one_at_a_time(asyncio.Lock()))
):
    if (ADAPTERS_DIRECTORY / request.id).exists():
        return {"lora_path": ADAPTERS_DIRECTORY / request.id}

    token_ids = cast(
        list[int],
        TOKENIZER(
            request.text,
            truncation=False,
            padding=False,
            pad_to_multiple_of=request.block_size,
        )["input_ids"],
    )

    def stream():
        for i in range(0, len(token_ids), request.block_size):
            yield {
                "input_ids": token_ids[i : i + request.block_size],
            }

    dataset = cast(
        Dataset,
        Dataset.from_generator(  # pyright: ignore[reportUnknownMemberType]
            stream
        ),
    )

    dataset = dataset.train_test_split()
    train_dataset = dataset["train"]
    eval_dataset = dataset["test"]

    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        inference_mode=False,
        r=request.lora_rank,
        lora_alpha=request.lora_alpha,
        lora_dropout=request.lora_dropout,
    )

    model = get_peft_model(MODEL, lora_config)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            per_device_train_batch_size=request.per_device_train_batch_size,
            num_train_epochs=request.num_train_epochs,
            learning_rate=request.learning_rate,
            logging_steps=1,
            metric_for_best_model="loss",
            eval_strategy="epoch",
            ddp_find_unused_parameters=False,  # https://discuss.huggingface.co/t/training-llama-with-lora-on-multiple-gpus-may-exist-bug/47005/2
        ),
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        callbacks=[
            EarlyStoppingCallback(
                early_stopping_patience=5,
                early_stopping_threshold=0.01,
            )
        ],
        data_collator=DATA_COLLATOR,
    )

    trainer.train()  # pyright: ignore[reportUnknownMemberType]

    model.save_pretrained(  # pyright: ignore[reportUnknownMemberType]
        str(ADAPTERS_DIRECTORY / request.id),
        safe_serialization=True,
    )
    TOKENIZER.save_pretrained(ADAPTERS_DIRECTORY / request.id)  # pyright: ignore[reportUnknownMemberType]

    model.unload()  # pyright: ignore[reportCallIssue]

    gc.collect()
    torch.cuda.empty_cache()

    return {"lora_path": str(ADAPTERS_DIRECTORY / request.id)}


async def _one_at_a_time(lock: asyncio.Lock):
    async with lock:
        yield
