import requests
from urllib.parse import urljoin
import pandas as pd
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import threading


class HTTPRequest:
    def __init__(self, base_url, log_callback=None):
        self.base_url = base_url.rstrip("/")
        self.cookies = {}
        self.log_callback = log_callback  # 로그 출력 콜백 함수

    def set_cookies(self, cookies):
        self.cookies = cookies

    def get(self, endpoint):
        url = urljoin(self.base_url, endpoint)
        try:
            response = requests.get(url, cookies=self.cookies, timeout=5)
            response.raise_for_status()
            return {"status_code": response.status_code, "content": response.text[:200]}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}

    def scan_url(self, paths):
        results = {}
        for path in paths:
            log_message = f"Scanning: {path}..."
            if self.log_callback:
                self.log_callback(log_message)  # GUI에 로그 출력
            result = self.get(path)
            results[path] = result
            time.sleep(1)  # 요청 간 1초 대기
        return results


def load_paths_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            paths = [line.strip() for line in file if line.strip()]
            paths = [path if path.startswith("/") else f"/{path}" for path in paths]
        return paths
    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found: {file_path}")
        return []


def save_results_to_excel(results, file_path):
    # 각 상태 코드 범위에 따른 분류
    status_100 = []
    status_200 = []
    status_300 = []
    status_400 = []
    status_500 = []
    errors = []

    for path, result in results.items():
        if "error" in result:
            errors.append({"Path": path, "Error": result["error"]})
        elif 100 <= result["status_code"] < 200:
            status_100.append({"Path": path, "Status Code": result["status_code"]})
        elif 200 <= result["status_code"] < 300:
            status_200.append({"Path": path, "Status Code": result["status_code"]})
        elif 300 <= result["status_code"] < 400:
            status_300.append({"Path": path, "Status Code": result["status_code"]})
        elif 400 <= result["status_code"] < 500:
            status_400.append({"Path": path, "Status Code": result["status_code"]})
        elif 500 <= result["status_code"] < 600:
            status_500.append({"Path": path, "Status Code": result["status_code"]})

    # DataFrames 생성
    data_frames = {
        "100 Responses": status_100,
        "200 Responses": status_200,
        "300 Responses": status_300,
        "400 Responses": status_400,
        "500 Responses": status_500,
        "Errors": errors,
    }

    # 엑셀 파일로 저장
    with pd.ExcelWriter(file_path) as writer:
        for sheet_name, data in data_frames.items():
            if data:  # 데이터가 비어 있지 않은 경우만 저장
                pd.DataFrame(data).to_excel(writer, sheet_name=sheet_name, index=False)

    print(f"스캔 결과가 엑셀 파일에 저장되었습니다: {file_path}")


def start_scan_thread():
    # 스캔 작업을 별도의 스레드에서 실행
    threading.Thread(target=start_scan).start()


def start_scan():
    base_url = url_entry.get().strip()
    if not base_url:
        messagebox.showerror("Error", "Please enter a base URL.")
        return

    paths_file = paths_file_var.get()
    if not paths_file:
        messagebox.showerror("Error", "Please select a paths file.")
        return

    output_file = output_file_var.get()
    if not output_file:
        messagebox.showerror("Error", "Please select a result file path.")
        return

    cookies_input = cookies_entry.get().strip()
    cookies = {}
    if cookies_input:
        try:
            cookies = {kv.split("=")[0].strip(): kv.split("=")[1].strip() for kv in cookies_input.split(";")}
        except Exception:
            messagebox.showerror("Error", "Invalid cookie format. Use key=value; key2=value2 format.")
            return

    paths = load_paths_from_file(paths_file)
    if not paths:
        messagebox.showerror("Error", "No valid paths found in the file.")
        return

    try:
        def log_to_gui(message):
            log_textbox.insert(tk.END, message + "\n")
            log_textbox.see(tk.END)  # 스크롤을 최신 로그로 이동

        client = HTTPRequest(base_url, log_callback=log_to_gui)
        client.set_cookies(cookies)  # 쿠키 설정
        scan_results = client.scan_url(paths)
        save_results_to_excel(scan_results, output_file)
        messagebox.showinfo("Success", f"Scan complete! Results saved to: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def select_paths_file():
    file_path = filedialog.askopenfilename(title="Select Paths File", filetypes=[("Text Files", "*.txt")])
    if file_path:
        paths_file_var.set(file_path)


def select_output_file():
    file_path = filedialog.asksaveasfilename(
        title="Select Output File", defaultextension=".xlsx", filetypes=[("Excel Files", "*.xlsx")]
    )
    if file_path:
        output_file_var.set(file_path)


# Create GUI
root = tk.Tk()
root.title("URL Scanner")
root.geometry("700x500")

# Base URL input
tk.Label(root, text="Base URL:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
url_entry = tk.Entry(root, width=50)
url_entry.grid(row=0, column=1, padx=10, pady=10)

# Paths file selection
tk.Label(root, text="Paths File:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
paths_file_var = tk.StringVar()
paths_file_entry = tk.Entry(root, textvariable=paths_file_var, width=50)
paths_file_entry.grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=select_paths_file).grid(row=1, column=2, padx=10, pady=10)

# Output file selection
tk.Label(root, text="Result File:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
output_file_var = tk.StringVar()
output_file_entry = tk.Entry(root, textvariable=output_file_var, width=50)
output_file_entry.grid(row=2, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=select_output_file).grid(row=2, column=2, padx=10, pady=10)

# Cookies input
tk.Label(root, text="Cookies:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
cookies_entry = tk.Entry(root, width=50)
cookies_entry.grid(row=3, column=1, padx=10, pady=10)

# Log display
tk.Label(root, text="Log:").grid(row=4, column=0, padx=10, pady=10, sticky="ne")
log_textbox = tk.Text(root, width=80, height=10, state="normal", bg="black", fg="white")
log_textbox.grid(row=4, column=1, columnspan=2, padx=10, pady=10)

# Start button
tk.Button(root, text="Start Scan", command=start_scan_thread, bg="green", fg="red").grid(row=5, column=1, pady=20)

root.mainloop()
