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

organization = "skax-internal"

base_url = "https://api.github.com"

headers = {
    "Authorization": f"token {github_token}",
    "Accept": "application/vnd.github.v3+json",
}


def list_branches(repo_owner, repo_name):
    """GitHub API를 이용해 특정 리포지토리의 브랜치 목록을 조회합니다.

    Args:
        repo_owner: 저장소 소유자 (예: 'octocat')
        repo_name: 저장소 이름 (예: 'Hello-World')
        token: GitHub Personal Access Token

    Returns:
        브랜치 이름 리스트

    """
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/branches"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        raise Exception(f"Failed to get branches: {response.json()}")

    branches = [branch["name"] for branch in response.json()]
    return branches


def create_branch(repo_owner, repo_name, new_branch, base_branch):
    """GitHub API를 이용해 새로운 브랜치를 생성합니다.

    :param repo_owner: 저장소 소유자 (예: 'octocat')
    :param repo_name: 저장소 이름 (예: 'Hello-World')
    :param new_branch: 새로 만들 브랜치 이름 (예: 'feature-xyz')
    :param base_branch: 기준이 되는 브랜치 이름 (예: 'main')
    :param token: GitHub Personal Access Token

    """
    # 1. 기준 브랜치의 최신 커밋 SHA 가져오기
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        raise Exception(f"Failed to get base branch: {response.json()}")
    sha = response.json()["object"]["sha"]

    # 2. 새 브랜치 생성
    create_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/refs"
    data = {"ref": f"refs/heads/{new_branch}", "sha": sha}
    create_response = requests.post(create_url, headers=headers, json=data, timeout=10)
    if create_response.status_code != 201:
        # raise Exception(f"[{repo_name}] Failed to create branch: {create_response.json()}")
        print(f"[{repo_name}] Failed to create branch: {create_response.json()}")

    print(f"✅ Branch '{new_branch}' created from '{base_branch}'")
    return create_response.json()


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


def update_secret(repo, secret_name, secret_value, public_key_id, public_key):
    """리포지토리의 GitHub Actions 시크릿을 업데이트합니다."""
    url = f"{base_url}/repos/{repo}/actions/secrets/{secret_name}"

    encrypted_value = encrypt_value(public_key, secret_value)
    payload = {
        "encrypted_value": encrypted_value,
        "key_id": public_key_id,
    }

    response = requests.put(url, headers=headers, json=payload, timeout=10)

    if response.status_code == 204:
        print(f"Secret {secret_name} updated in {repo}")
    else:
        print(f"Failed to update secret {secret_name} in {repo}: {response.status_code}")


def get_variables(repo):
    """리포지토리의 GitHub Actions 변수를 이름과 값 튜플 목록으로 반환합니다."""
    url = f"{base_url}/repos/{repo}/actions/variables"
    # print(url)
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
    print(url)
    payload = {"name": var_name, "value": var_value}
    response = requests.post(url, headers=headers, json=payload, timeout=10)
    print(response)
    if response.status_code == 201:
        print(f"Variable {var_name} created in {repo}")
    else:
        print(f"Failed to create variable {var_name} in {repo}: {response.status_code}")


def update_variable(repo, var_name, var_value):
    """리포지토리의 GitHub Actions 변수를 업데이트합니다."""
    url = f"{base_url}/repos/{repo}/actions/variables/{var_name}"
    payload = {"name": var_name, "value": var_value}
    response = requests.patch(url, headers=headers, json=payload, timeout=10)

    if response.status_code == 204:
        print(f"Variable {var_name} updated in {repo}")
    else:
        print(f"Failed to update variable {var_name} in {repo}: {response.status_code}")


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


def load_repos_from_file(filepath="repos.txt"):
    """텍스트 파일에서 리포지토리 쌍 목록을 읽어 반환합니다.

    각 줄은 콤마로 구분된 2개의 리포지토리 또는 단일 리포지토리를 포함할 수 있습니다.
    """
    repos = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # 콤마로 구분된 경우
                if "," in line:
                    parts = [part.strip() for part in line.split(",")]
                    if len(parts) == 2:
                        repos.append((parts[0], parts[1]))
                # 단일 값인 경우
                else:
                    repos.append((line))

        return repos
    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {filepath}")
        return []
    except Exception as e:
        print(f"파일 처리 오류: {e}")
        return []


def migrate_variables(repos):
    """변수 마이그레이션 메인 함수."""
    for repo in repos:
        source_repo = repo[0]
        target_repo = repo[1]

        variables = get_variables(source_repo)
        print(f"repo_name: {source_repo} {target_repo}")
        print(variables)

        for var_name, var_value in variables:
            create_variable(target_repo, var_name, var_value)
            # print(var_name, var_value)


def migrate_secrets(repos):
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
