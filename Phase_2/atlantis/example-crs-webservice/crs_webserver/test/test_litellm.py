import os
from my_crs.crs_manager.litellm_adaptor import create_budget, create_llm_key, info_budget, spend_logs, delete_budget, create_user, info_user, info_llm_key, delete_user
from loguru import logger


def test_create_budget():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"

    d = delete_budget("CRS_patch")
    logger.info(d)
    
    b = create_budget("CRS_patch", 1)
    logger.info(b)
    
    b = info_budget("CRS_patch")
    logger.info(b)

def test_info_budget():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    b = info_budget("CRS_patch")
    logger.info(b)

def test_create_llm_key():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    key = create_llm_key("CRS_patch")
    logger.info(f"key: {key}")

def test_spend_logs():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    c = spend_logs("sk-Zd4gK4awFWLfluBrSMkcag")
    logger.info(c)


def test_create_user():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    u = create_user("CRS_patch")
    logger.info(u)

def test_info_user():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    u = info_user("CRS_patch")
    logger.info(u)

def test_info_key():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    key = "sk-BFQZkjjwliZpbIA4_UPhpw"
    k = info_llm_key(key)
    logger.info(k)

def test_delete_user():
    os.environ["LITELLM_URL"] = "http://localhost:4000/"
    os.environ["LITELLM_MASTER_KEY"] = "sk-1234"
    u = delete_user("CRS_patch")
    logger.info(u)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == "cu":
            test_create_user()
        elif sys.argv[1] == "ck":
            test_create_llm_key()
        elif sys.argv[1] == "cb":
            test_create_budget()
        elif sys.argv[1] == "s":
            test_spend_logs()
        elif sys.argv[1] == "ib":
            test_info_budget()
        elif sys.argv[1] == "iu":
            test_info_user()
        elif sys.argv[1] == "ik":
            test_info_key()
        elif sys.argv[1] == "du":
            test_delete_user()


    