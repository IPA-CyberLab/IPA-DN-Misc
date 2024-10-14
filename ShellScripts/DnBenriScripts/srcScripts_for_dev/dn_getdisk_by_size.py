import os
import json
import subprocess
import inspect
import sys
import time as systime
import argparse
import shutil

from typing import List, Tuple, Dict, Set, Callable, TypeVar, Type
from datetime import timedelta, tzinfo, timezone, time, date, datetime



class Str:
    NEWLINE_CELF = "\r\n"
    NEWLINE_CR = "\r"
    NEWLINE_LF = "\n"

    # 文字列を大文字・小文字を区別して比較
    @staticmethod
    def IsSame(s1: str, s2: str) -> bool:
        return Str.StrCmp(s1, s2)

    @staticmethod
    def StrCmp(s1: str, s2: str) -> bool:
        s1 = Str.NonNull(s1)
        s2 = Str.NonNull(s2)
        return s1 == s2

    @staticmethod
    def Cmp(s1: str, s2: str) -> int:
        return Str.StrCmpRetInt(s1, s2)

    @staticmethod
    def StrCmpRetInt(s1: str, s2: str) -> int:
        s1 = Str.NonNull(s1)
        s2 = Str.NonNull(s2)
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return 1
        return -1

    # 文字列を大文字・小文字を区別せずに比較
    @staticmethod
    def IsSamei(s1: str, s2: str) -> bool:
        return Str.StrCmpi(s1, s2)

    @staticmethod
    def StrCmpi(s1: str, s2: str) -> bool:
        s1 = Str.NonNull(s1).lower()
        s2 = Str.NonNull(s2).lower()
        return s1 == s2

    @staticmethod
    def Cmpi(s1: str, s2: str) -> int:
        return Str.StrCmpRetInti(s1, s2)

    @staticmethod
    def StrCmpRetInti(s1: str, s2: str) -> int:
        s1 = Str.NonNull(s1).lower()
        s2 = Str.NonNull(s2).lower()
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return 1
        return -1
    
    # 複数の文字列を置換する
    @staticmethod
    def ReplaceMultiStr(src: str, replaceList: Dict[str, str], caseSensitive: bool = False) -> str:
        src = Str.NonNull(src)
        for key, value in replaceList.items():
            src = Str.ReplaceStr(src, key, value, caseSensitive)
        return src

    # 文字列を置換する
    @staticmethod
    def ReplaceStr(str: str, oldKeyword: str, newKeyword: str, caseSensitive: bool = False) -> str:
        str = Str.NonNull(str)
        if Str.IsNullOrZeroLen(str):
            return ""
        oldKeyword = Str.NonNull(oldKeyword)
        newKeyword = Str.NonNull(newKeyword)
        if Str.IsNullOrZeroLen(oldKeyword):
            return str

        i = 0
        j = 0
        num = 0
        sb = ""

        len_string = len(str)
        len_old = len(oldKeyword)
        len_new = len(newKeyword)

        while True:
            i = Str.SearchStr(str, oldKeyword, i, caseSensitive)
            if i == -1:
                sb += str[j:]
                break
            num += 1
            sb += str[j:i]
            sb += newKeyword

            i += len_old
            j = i

        return sb

    # 文字列を検索する
    @staticmethod
    def SearchStr(str: str, keyword: str, start: int = 0, caseSensitive: bool = False) -> int:
        str = Str.NonNull(str)
        keyword = Str.NonNull(keyword)
        if Str.IsNullOrZeroLen(str) or Str.IsNullOrZeroLen(keyword):
            return -1
        if not caseSensitive:
            str = str.lower()
            keyword = keyword.lower()
        return str.find(keyword, start)

    # 文字列が含まれるか?
    @staticmethod
    def InStr(str: str, keyword: str, caseSensitive: bool = False) -> bool:
        str = Str.NonNull(str)
        keyword = Str.NonNull(keyword)
        if Str.IsNullOrZeroLen(str) or Str.IsNullOrZeroLen(keyword):
            return False
        if not caseSensitive:
            str = str.lower()
            keyword = keyword.lower()
        return keyword in str

    @staticmethod
    def GetLines(src: str, removeEmpty: bool = False, trim: bool = False) -> List[str]:
        ret: List[str] = list()
        for line in Str.NonNull(src).splitlines():
            if trim:
                line = Str.Trim(line)

            if not removeEmpty or Str.IsFilled(line):
                ret.append(line)
        return ret

    @staticmethod
    def IsNullOrZeroLen(str: str) -> bool:
        if Str.IsNull(str) or len(str) == 0:
            return True
        return False

    @staticmethod
    def IsNull(str: str) -> bool:
        return Util.IsNull(str)

    @staticmethod
    def IsNonNull(str: str) -> bool:
        return not Str.IsNull(str)

    @staticmethod
    def ToStr(str: any) -> str:
        if Util.IsNull(str):
            return ""

        if Util.IsType(str, "str"):
            return str

        return F"{str}"

    @staticmethod
    def NonNull(str: str) -> str:
        if Str.IsNull(str):
            return ""

        return str

    @staticmethod
    def StrToInt(str: str) -> int:
        try:
            if Str.IsNull(str):
                return 0
            i = int(str)
            return i
        except:
            return 0

    @staticmethod
    def Trim(str: str) -> str:
        return Str.NonNull(str).strip()

    @staticmethod
    def IsEmpty(str: str) -> bool:
        if Str.Len(Str.Trim(str)) == 0:
            return True
        return False

    @staticmethod
    def IsFilled(str: str) -> bool:
        return not Str.IsEmpty(str)

    @staticmethod
    def Len(str: str) -> int:
        if Str.IsNull(str):
            return 0

        return len(str)

    @staticmethod
    def ToBool(str: str) -> bool:
        i = Str.StrToInt(str)
        if i != 0:
            return True

        tmp = Str.Trim(str).lower()

        if Str.Len(tmp) >= 1:
            if tmp[0] == 'y' or tmp[0] == 't':
                return True
            if tmp.startswith("ok") or tmp.startswith("on") or tmp.startswith("enable"):
                return True

        return False

    @staticmethod
    def GetStr(object: any) -> str:
        if object is None:
            return "None"

        if Util.IsTypeOf(object, str):
            return object

        if Util.IsTypeOf(object, Exception):
            return F"{object}"

        if Util.IsSimpleValue(object):
            return str(object)

        return Json.ObjectToJson(object)

    @staticmethod
    def Combine(strList: list, splitStr: str = ", ", removeEmpty: bool = False) -> str:
        ret = ""
        tmpList: List[str] = list()

        for item in strList:
            s = Str.GetStr(item)
            if not removeEmpty or Str.IsFilled(s):
                tmpList.append(s)

        num = len(tmpList)
        for i in range(num):
            ret += tmpList[i]

            if i != (num - 1):
                ret += splitStr

        return ret
    
    @staticmethod
    def GetFirstFilledLine(src: str) -> str:
        src = Str.GetStr(src)
        lines = Str.GetLines(src, removeEmpty=True, trim=True)
        for line in lines:
            return line
        return ""

    @staticmethod
    def OneLine(src: str, splitStr: str = " / ", removeEmpty: bool = True) -> str:
        src = Str.GetStr(src)
        lines = Str.GetLines(src, removeEmpty=True, trim=True)
        return Str.Combine(lines, splitStr, removeEmpty)
    
    @staticmethod
    def NormalizeFqdn(src: str) -> str:
        s = Str.Trim(src).lower()
        tokens = s.split(".")
        o: List[str] = list()
        for token in tokens:
            if Str.IsFilled(token):
                for c in token:
                    if not ((c >= "a" and c <= "z") or (c >= "0" and c <= "9") or c == "-" or c == "_"):
                        raise Err(f"Invalid FQDN: '{src}'")
                o.append(token)
        ret = Str.Combine(o, ".", removeEmpty=True)
        if Str.IsEmpty(ret):
            raise Err(f"Invalid FQDN: '{src}'")
        return ret
    
    @staticmethod
    def DecodeUtf8(src: bytes) -> str:
        if Util.IsNull(src):
            return ""
        return Str.NonNull(src.decode("utf-8"))
    
    @staticmethod
    def EncodeUtf8(src: str) -> bytes:
        src = Str.NonNull(src)
        return src.encode("utf-8")

def Print(obj: any) -> str:
    s = Str.GetStr(obj)
    print(s)
    return s

def PrintLog(obj:any) -> str:
    s = Str.GetStr(obj)
    print(f"{Time.NowLocal()}: {s}")
    return s


def GetStr(obj: any) -> str:
    return Str.GetStr(obj)

def DoNothing():
    return 0

def NoOp():
    return 0

class Util:
    @staticmethod
    def ToBool(object: any) -> bool:
        if Util.IsType(object, "str"):
            return Str.ToBool(str)

        if not (object):
            return False

        return True

    @staticmethod
    def IsNull(object: any) -> bool:
        if object is None:
            return True

        return False

    @staticmethod
    def GetTypeName(object: any) -> str:
        return type(object).__name__

    @staticmethod
    def IsType(object: any, typeName: str) -> bool:
        if Util.GetTypeName(object) == typeName:
            return True

        return False

    @staticmethod
    def IsTypeOf(object: any, baseType: type) -> bool:
        return isinstance(object, baseType)

    @staticmethod
    def IsBinary(object: any) -> bool:
        return Util.IsType(object, "bytes")

    @staticmethod
    def IsClass(object: any) -> bool:
        return hasattr(object, "__dict__")

    @staticmethod
    def IsPrimitive(object: any) -> bool:
        if Util.IsNull(object):
            return True
        return isinstance(object, (int, float, bool, str, bytes, bytearray, memoryview))

    @staticmethod
    def IsSimpleValue(object: any) -> bool:
        if Util.IsPrimitive(object):
            return True
        return isinstance(object, (datetime))

    @staticmethod
    def GetClassAttributes(object: any) -> dict:
        if Util.IsClass(object):
            return object.__dict__
        raise Err("Not a class object.")

    @staticmethod
    def GetClassAttributesOrItself(object: any):
        if Util.IsClass(object):
            return Util.GetClassAttributes(object)
        return object
    
    @staticmethod
    def GenRandInterval(standard: float, plusMinusPercentage: float = 30.0) -> float:
        rate = plusMinusPercentage * (Rand.SInt31() % 10000) / 10000.0 / 100.0
        v = standard * rate
        if (v == 0.0):
            return standard
        b = Rand.Bool()
        if b:
            ret = standard + standard * rate
        else:
            ret = standard - standard * rate
        return max(ret, 0.001)
    
    @staticmethod
    def GetSingleHostCertAndIntermediateCertsFromCombinedCert(src: str) -> Tuple[str, str]:
        lines = Str.GetLines(src, trim=True)
        flag = 0

        cert0_body = ""
        cert1_body = ""

        current_cert = ""
        cert_index = 0

        for line in lines:
            if line == "-----BEGIN CERTIFICATE-----":
                flag = 1
                current_cert += line + "\n"
            elif line == "-----END CERTIFICATE-----":
                flag = 0
                current_cert += line + "\n"
                if cert_index == 0:
                    cert0_body = current_cert
                else:
                    cert1_body += current_cert
                    cert1_body += "\n"
                cert_index += 1
                current_cert = ""
            else:
                if flag == 1:
                    current_cert += line + "\n"
        
        return (cert0_body, cert1_body)

class EasyExecResults:
    Result: subprocess.CompletedProcess
    IsOk: bool
    StdOut: str
    StdErr: str
    StdOutAndErr: str
    ExitCode: int
    Cmd: List[str]

    def InitFromCompletedProcess(self, res: subprocess.CompletedProcess, cmd: List[str]):
        self.Result = res
        self.ExitCode = res.returncode
        self.IsOk = (res.returncode == 0)
        self.StdOut = Str.ToStr(res.stdout)
        self.StdErr = Str.ToStr(res.stderr)
        self.StdOutAndErr = self.StdOut + "\n" + self.StdErr + "\n"
        self.Cmd = cmd

    def ThrowIfError(self):
        if not self.IsOk:
            errOneLine = Str.OneLine(self.StdErr)
            outOneLine = Str.OneLine(self.StdOut)
            tmp = f"Command '{self.Cmd}' returned exit code {self.ExitCode}."
            if Str.IsFilled(errOneLine):
                tmp += f" Error string: {errOneLine}"
            if Str.IsFilled(outOneLine):
                tmp += f" Output string: {outOneLine}"

            raise Err(tmp)


class EasyExec:
    @staticmethod
    # 注意! timeoutSecs でタイムアウトを指定し、タイムアウト発生時には kill するためには、shell = False にしなければならない。
    def Run(command: List[str], shell: bool = True, ignoreError: bool = False, timeoutSecs: int = None):
        if shell and timeoutSecs is not None:
            raise Err("shell == True and timeoutSecs is not None.")

        res = subprocess.run(command, shell=shell,
                             encoding="utf-8", text=True, timeout=timeoutSecs)
        
        if not ignoreError:
            res.check_returncode()

    @staticmethod
    # 注意! timeoutSecs でタイムアウトを指定し、タイムアウト発生時には kill するためには、shell = False にしなければならない。
    def RunPiped(command: List[str], shell: bool = True, ignoreError: bool = False, timeoutSecs: int = None) -> EasyExecResults:
        if shell and timeoutSecs is not None:
            raise Err("shell == True and timeoutSecs is not None.")

        res = subprocess.run(command, shell=shell, encoding="utf-8", text=True,
                             timeout=timeoutSecs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        ret = EasyExecResults()
        ret.InitFromCompletedProcess(res, command)

        if not ignoreError:
            ret.ThrowIfError()

        return ret

    @staticmethod
    def RunBackground(command: List[str], shell: bool = True, cwd: str = None, stdin=None, stdout=None, stderr=None) -> subprocess.Popen:
        res = subprocess.Popen(command, shell=shell, text=True,
                               cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr)

        return res

class Err(Exception):
    def __init__(self, str: str):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("id", metavar="<id>", type=str, help="Size")

    args = parser.parse_args()
    id = args.id

    result = EasyExec.RunPiped("/usr/bin/lsblk --raw --bytes --noheadings --all".split(), shell=False,
            timeoutSecs=30)

    lines = Str.GetLines(result.StdOut)

    dev_and_size_list = []

    for line in lines:
        line = Str.Trim(line)
        if Str.IsFilled(line):
            tokens = line.split(" ")
            if len(tokens) >= 6:
	            if tokens[5] == "disk":
		            dev_and_size_list.append((tokens[0], tokens[3]))

    dev_and_size_list.sort(key=lambda x:x[0])

    ret = ""

    num = 0

    for element in dev_and_size_list:
        if Str.IsSamei(element[1], id):
            if Str.IsEmpty(ret):
                ret = element[0]
            num += 1

    if Str.IsEmpty(ret):
        ret = "ERROR_NOT_FOUND_DISK_SIZE"
    
    if num >= 2:
        ret = "ERROR_DUPLICATED_DISK_SIZE"

    print(ret)


    

    

