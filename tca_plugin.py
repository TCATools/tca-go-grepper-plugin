# -*- encoding: utf-8 -*-
'''
go-grepper
'''
import os
import yaml
import json
import platform
import subprocess

PWD = os.getcwd()
WOORK_DIR = os.environ.get("RESULT_DIR")
SOURCE_DIR = os.environ.get("SOURCE_DIR")

def decode_str(text) -> str:
    try:
        return text.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")

def get_task_params():
    """
    获取需要任务参数
    :return:
    """
    task_request_file = os.environ["TASK_REQUEST"]
    with open(task_request_file, "r") as rf:
        task_request = json.load(rf)
    task_params = task_request["task_params"]
    return task_params

class Grepper():

    def __init__(self, params):
        self.params = params
        self.tool = self._get_tool()

    def _get_tool(self) -> str:
        system = platform.system()
        if system == "Linux":
            if platform.machine() == "aarch64":
                return os.path.join(PWD, "bin", "linux", "arm64", "go-grepper")
            else:
                return os.path.join(PWD, "bin", "linux", "amd64", "go-grepper")
        elif system == "Darwin":
            if platform.machine() == "aarch64":
                return os.path.join(PWD, "bin", "darwin", "arm64", "go-grepper")
            else:
                return os.path.join(PWD, "bin", "darwin", "amd64", "go-grepper")
        elif system == "Windows":
            return os.path.join(PWD, "bin", "windows", "amd64", "go-grepper.exe")
        else:
            raise Exception("未支持的系统平台或者无法识别的系统平台")

    def _get_config(self, rules : list) -> str:
        custom_config = os.environ.get("GO_GREPPER_CONFIG")
        if custom_config and os.path.exists(os.path.join(SOURCE_DIR, custom_config)):
            return os.path.join(SOURCE_DIR, custom_config)
        tca_config = os.path.join(WOORK_DIR, "tca-go-grepper-config.yaml")
        rule_names = list()
        for rule in rules:
            rule_name = rule["name"]
            rule_names.append(rule_name)
        re_path_exclude : list[str] = self.params["path_filters"].get("re_exclusion", ["vendors/.*", ".*/vendors/.*"])
        confi_params = dict()
        confi_params["exclude-path-regexps"] = re_path_exclude
        with open(tca_config, "w", encoding="utf-8") as fw:
            yaml.dump(confi_params, fw, default_flow_style=False)
        return tca_config


    def analyze(self) -> list:
        print("当前使用的工具：" + self.tool)
        issues = []
        issues_file = os.path.join(WOORK_DIR, "go-grepper-result.json")
        scan_cmd = [self.tool, "scan", "-t", SOURCE_DIR, "-f", "json", "-o", issues_file]
        # rules去重
        rule_list = self.params["rule_list"]
        rule_names = set()
        rules = []
        for r in rule_list:
            if r["name"] not in rule_names:
                rule_names.add(r["name"])
                rules.append(r)
        # 如果未指定配置文件，则使用默认配置
        config_file = self._get_config(rules)
        scan_cmd.extend(["--config", config_file])
        print(scan_cmd)
        sp = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = sp.communicate(timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "6000")))
        if stderr:
            stderr_str = decode_str(stderr)
            print(stderr_str)
        # 分析异常时可能生成空文件导致读取异常
        try:
            with open(issues_file, "r") as fr:
                datas = json.load(fp=fr)
            # 无问题时datas为None
            if not datas:
                print("datas is None!")
                return issues
        except Exception as err:
            print(f"解析结果异常: {err}")
            return issues
        results = datas["results"]
        if not results:
            return issues
        for data in results:
            issue_rule = data["rule_id"]
            issue_msg = data["description"]
            issue_file = data["file_name"]
            issue_line = data["line_number"]
            issue_col = 0
            issues.append(
                {
                    "path": issue_file,
                    "rule": issue_rule,
                    "msg": issue_msg,
                    "line": issue_line,
                    "column": issue_col,
                }
            )
        return issues


if __name__ == "__main__":
    params = get_task_params()
    tool = Grepper(params)
    result_file = os.path.join(WOORK_DIR, "result.json")
    issues = tool.analyze()
    with open(result_file, "w") as fw:
        json.dump(issues, fw, indent=2)
