import base64
import os

import requests
from dotenv import load_dotenv
from nacl import encoding, public

load_dotenv()

# `.env` 또는 환경변수에서 토큰을 읽습니다.
github_token = os.getenv("GITHUB_TOKEN")
if not github_token:
    raise RuntimeError("환경변수 GITHUB_TOKEN이 설정되어 있지 않습니다. .env 파일 또는 환경변수에 토큰을 추가하세요.")

organization = "skccmygit"

base_url = "https://api.github.com"

headers = {
    "Authorization": f"token {github_token}",
    "Accept": "application/vnd.github.v3+json",
}


def get_secrets(repo):
    """리포지토리의 GitHub Actions 시크릿 이름 목록을 반환합니다."""
    url = f"{base_url}/repos/{repo}/actions/secrets"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        secrets = response.json().get("secrets")
        return [secrets["name"] for secrets in secrets]
    else:
        print(f"Failed to fetch secrets from {repo}: {response.status_code}")
        return []


def encrypt_value(public_key, secret_value):
    """공개키로 값을 암호화하여 base64 인코딩된 문자열을 반환합니다."""
    try:
        public_key_bytes = public_key.encode("utf-8")
        decorded_public_key = public.PublicKey(public_key_bytes, encoding.Base64Encoder())
        sealed_box = public.SealedBox(decorded_public_key)
        encrypted_bytes = sealed_box.encrypt(secret_value.encode("utf-8"))

        return base64.b64encode(encrypted_bytes).decode("utf-8")
    except Exception as e:
        print(f"Encryption error: {e}")
        return None


def create_secret(repo, secret_name, secret_value, public_key_id, public_key):
    """암호화된 시크릿을 대상 리포지토리에 생성합니다."""
    url = f"{base_url}/repos/{repo}/actions/secrets/{secret_name}"

    encrypted_value = encrypt_value(public_key, secret_value)
    payload = {
        "encrypted_value": encrypted_value,  # 암호화된 값
        "key_id": public_key_id,  # github Actions 공개 키 ID
    }

    response = requests.put(url, headers=headers, json=payload, timeout=10)

    if response.status_code == 201:
        print(f"Secret {secret_name} created in {repo}")
    else:
        print(f"Failed to create secret {secret_name} in {repo}: {response.status_code}")


def get_variables(repo):
    """리포지토리의 GitHub Actions 변수를 이름과 값 튜플 목록으로 반환합니다."""
    url = f"{base_url}/repos/{repo}/actions/variables"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        variables = response.json().get("variables")
        return [(var["name"], var["value"]) for var in variables]
    else:
        print(f"Failed to fetch variables from {repo}: {response.status_code}")
        return []


def create_variable(repo, var_name, var_value):
    """리포지토리에 GitHub Actions 변수를 생성합니다."""
    url = f"{base_url}/repos/{repo}/actions/variables"
    payload = {"name": var_name, "value": var_value}
    response = requests.post(url, headers=headers, json=payload, timeout=10)
    if response.status_code == 201:
        print(f"Variable {var_name} created in {repo}")
    else:
        print(f"Failed to create variable {var_name} in {repo}: {response.status_code}")


def get_github_public_key(repo):
    """리포지토리의 Actions 공개키 ID와 키를 반환합니다."""
    url = f"{base_url}/repos/{repo}/actions/secrets/public-key"
    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code == 200:
        public_key_info = response.json()
        public_key_id = public_key_info.get("key_id")
        public_key = public_key_info.get("key")
        return public_key_id, public_key
    else:
        print(f"Failed to fetch public key from {repo}: {response.status_code}")
        return None


def get_repo_list(prefix=None):
    """조직의 리포지토리 목록을 가져와 이름 리스트로 반환합니다."""
    url = f"{base_url}/orgs/{organization}/repos"
    params = {"per_page": 100}
    if prefix:
        params["name"] = prefix

    response = requests.get(url, headers=headers, params=params, timeout=10)
    if response.status_code == 200:
        repos = response.json()
        return [repo["name"] for repo in repos if prefix in repo["name"].lower()]

    else:
        print(f"Failed to fetch repositories: {response.status_code}")
        return []


repos = [
    (
        f"{organization}/abiz-gba-nc-backend",
        f"{organization}/hynix-abiz-gba-nc-backend",
    ),
    (f"{organization}/gba-ab-backend", f"{organization}/hynix-gba-ab-backend"),
    (f"{organization}/gba-airp-backend", f"{organization}/hynix-gba-airp-backend"),
    (f"{organization}/gba-ms", f"{organization}/hynix-gba-ms"),
]


def migrate_variables():
    """변수 마이그레이션 메인 함수."""
    for repo in repos:
        source_repo = repo[0]
        target_repo = repo[1]

        variables = get_variables(source_repo)
        # print(f"repo_name: {source_repo}")
        # print(variables)

        for var_name, var_value in variables:
            create_variable(target_repo, var_name, var_value)
            # print(var_name, var_value)


def migrate_secrets():
    """시크릿 마이그레이션 메인 함수."""
    for repo in repos:
        source_repo = repo[0]
        target_repo = repo[1]

        # print(f"repo_name: {source_repo}")
        # print(secrets)
        public_key_data = get_github_public_key(target_repo)
        if public_key_data:
            public_key_id = public_key_data[0]
            public_key = public_key_data[1]
            # print(f"public_key_id: {public_key_id}, public_key: {public_key}")

            if public_key and public_key_id:
                secret_value = "temp_value"  # noqa
                # print(encrypt_value(public_key, secret_value))

                secrets = get_secrets(source_repo)
                for secret_name in secrets:
                    create_secret(target_repo, secret_name, secret_value, public_key_id, public_key)


if __name__ == "__main__":
    migrate_secrets()
    migrate_variables()
