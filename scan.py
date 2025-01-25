import requests
from urllib.parse import urljoin
import pandas as pd
import time

class HTTPRequest:
    def __init__(self, base_url):
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = "http://" + base_url  # 기본적으로 http://를 추가
        self.base_url = base_url.rstrip("/")  # URL 끝의 '/' 제거
        self.cookies = {}  # 쿠키 저장용

    def set_cookies(self, cookies):
        """
        쿠키 값을 설정합니다.

        Args:
            cookies (dict): 쿠키 키-값 쌍.
        """
        self.cookies = cookies

    def get(self, endpoint, params=None, headers=None):
        """
        GET 요청을 보냅니다.

        Args:
            endpoint (str): 요청할 API의 엔드포인트.
            params (dict, optional): GET 요청의 쿼리 파라미터.
            headers (dict, optional): HTTP 요청 헤더.

        Returns:
            dict: 요청에 대한 응답 데이터를 반환.
        """
        url = urljoin(self.base_url, endpoint)  # URL 안전하게 결합
        try:
            response = requests.get(
                url, params=params, headers=headers, cookies=self.cookies, timeout=5
            )
            response.raise_for_status()
            return {"status_code": response.status_code, "content": response.text[:200]}  # 응답 텍스트는 일부만 반환
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def scan_url(self, paths):
        """
        주어진 경로 목록을 기반으로 URL을 스캔합니다.

        Args:
            paths (list): 검사할 경로 목록.

        Returns:
            dict: 각 경로에 대한 검사 결과.
        """
        results = {}
        for path in paths:
            print(f"Scanning: {path}...")
            result = self.get(path)
            results[path] = result
            time.sleep(1)
        return results


def load_paths_from_file(file_path):
    """
    텍스트 파일에서 스캔할 경로 목록을 로드합니다.

    Args:
        file_path (str): 경로가 저장된 텍스트 파일의 경로.

    Returns:
        list: 경로 목록.
    """
    try:
        with open(file_path, "r") as file:
            paths = [line.strip() for line in file.readlines() if line.strip()]
            paths = [path if path.startswith("/") else f"/{path}" for path in paths]
        return paths
    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {file_path}")
        return []


def save_results_to_excel(results, file_path):
    """
    스캔 결과를 엑셀 파일에 저장합니다.

    Args:
        results (dict): 스캔 결과.
        file_path (str): 저장할 파일 경로.
    """
    # 200대, 400대 상태 코드 및 기타 에러 분리
    status_200 = []
    status_400 = []
    errors = []

    for path, result in results.items():
        if "error" in result:
            errors.append({"Path": path, "Error": result["error"]})
        elif 200 <= result["status_code"] < 300:
            status_200.append({"Path": path, "Status Code": result["status_code"]})
        elif 400 <= result["status_code"] < 500:
            status_400.append({"Path": path, "Status Code": result["status_code"]})

    # DataFrames 생성
    df_200 = pd.DataFrame(status_200)
    df_400 = pd.DataFrame(status_400)
    df_errors = pd.DataFrame(errors)

    # 엑셀 파일로 저장
    with pd.ExcelWriter(file_path) as writer:
        if not df_200.empty:
            df_200.to_excel(writer, sheet_name="200 Responses", index=False)
        if not df_400.empty:
            df_400.to_excel(writer, sheet_name="400 Responses", index=False)
        if not df_errors.empty:
            df_errors.to_excel(writer, sheet_name="Errors", index=False)

    print(f"스캔 결과가 엑셀 파일에 저장되었습니다: {file_path}")


if __name__ == "__main__":
    base_url = input("스캔할 기본 URL을 입력하세요 (예: https://example.com): ")
    client = HTTPRequest(base_url)

    # 쿠키 설정 (필요 시)
    cookie_input = input("사용할 쿠키를 입력하세요 (key=value 형태로, 여러 개는 세미콜론으로 구분): ")
    if cookie_input.strip():
        cookies = {kv.split("=")[0].strip(): kv.split("=")[1].strip() for kv in cookie_input.split(";")}
        client.set_cookies(cookies)

    # 경로 목록 로드
    path_file = input("스캔할 경로가 저장된 파일의 경로를 입력하세요 (예: sensitive_paths.txt): ")
    paths_to_scan = load_paths_from_file(path_file)

    if not paths_to_scan:
        print("스캔할 경로가 없습니다. 파일을 확인하세요.")
    else:
        # URL 스캔
        scan_results = client.scan_url(paths_to_scan)

        # 결과 저장
        output_file = input("스캔 결과를 저장할 엑셀 파일 경로를 입력하세요 (예: scan_results.xlsx): ")
        save_results_to_excel(scan_results, output_file)
