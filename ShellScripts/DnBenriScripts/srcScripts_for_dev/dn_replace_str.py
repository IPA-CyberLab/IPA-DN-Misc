import os
import json
import subprocess
import inspect
import typing
import sys
import time as systime
import argparse
from typing import List, Tuple, Dict, Set, Callable, TypeVar, Type
from datetime import timedelta, tzinfo, timezone, time, date, datetime
    
def HasFileBom(filename):
    with open(filename, "r", encoding="utf-8") as f:
        first_line = f.readline()
        return (first_line[0] == "\ufeff")

def IsNullOrZeroLen(str: str) -> bool:
    if StrIsNull(str) or len(str) == 0:
        return True
    return False

def ReplaceStr(str: str, oldKeyword: str, newKeyword: str, caseSensitive: bool = False) -> str:
    str = NonNullStr(str)
    if IsNullOrZeroLen(str):
        return ""
    oldKeyword = NonNullStr(oldKeyword)
    newKeyword = NonNullStr(newKeyword)
    if IsNullOrZeroLen(oldKeyword):
        return str

    i = 0
    j = 0
    num = 0
    sb = ""

    len_string = len(str)
    len_old = len(oldKeyword)
    len_new = len(newKeyword)

    while True:
        i = SearchStr(str, oldKeyword, i, caseSensitive)
        if i == -1:
            sb += str[j:]
            break
        num += 1
        sb += str[j:i]
        sb += newKeyword

        i += len_old
        j = i

    return sb

def SearchStr(str: str, keyword: str, start: int = 0, caseSensitive: bool = False) -> int:
    str = NonNullStr(str)
    keyword = NonNullStr(keyword)
    if IsNullOrZeroLen(str) or IsNullOrZeroLen(keyword):
        return -1
    if not caseSensitive:
        str = str.lower()
        keyword = keyword.lower()
    return str.find(keyword, start)


def ObjIsNull(object: any) -> bool:
    if object is None:
        return True
    return False

def StrIsNull(str: str) -> bool:
    return ObjIsNull(str)
    
def NonNullStr(str: str) -> str:
    if StrIsNull(str):
        return ""
    return str

def StrTrim(str: str) -> str:
    return NonNullStr(str).strip()

def StrLen(str: str) -> int:
    if StrIsNull(str):
        return 0
    return len(str)

def IsSamei(s1: str, s2: str) -> bool:
    return StrCmpi(s1, s2)

def StrCmpi(s1: str, s2: str) -> bool:
    s1 = NonNullStr(s1).lower()
    s2 = NonNullStr(s2).lower()
    return s1 == s2

def IsSame(s1: str, s2: str) -> bool:
    return StrCmp(s1, s2)

def StrCmp(s1: str, s2: str) -> bool:
    s1 = NonNullStr(s1)
    s2 = NonNullStr(s2)
    return s1 == s2

def IsEmptyStr(str: str) -> bool:
    if StrLen(StrTrim(str)) == 0:
        return True
    return False

def IsFilledStr(str: str) -> bool:
    return not IsEmptyStr(str)

def GetLines(src: str, removeEmpty: bool = False, trim: bool = False) -> List[str]:
    ret = list()
    for line in NonNullStr(src).splitlines():
        if trim:
            line = StrTrim(line)

        if not removeEmpty or IsFilledStr(line):
            ret.append(line)
    return ret

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("src", metavar="<src>", type=str, help="Source filename")
    parser.add_argument("-d", dest="dst",
                        type=str, help="Destination filename")
    parser.add_argument("-i", dest="ignoreCase", action="store_true",
                        help="Ignore cases")
    parser.add_argument("-p", dest="partialMode", action="store_true",
                        help="Allow partial replacement in a line")
    parser.add_argument("-t", dest="trimMode", action="store_true",
                        help="Trim whitespaces")
    parser.add_argument("-a", dest="strA",
                        type=str, help="Search string (old string)")
    parser.add_argument("-b", dest="strB",
                        type=str, help="Replace string (new string)")
    args = parser.parse_args()
    src = args.src
    dst = args.dst
    ignoreCase = args.ignoreCase
    partialMode = args.partialMode
    trimMode = args.trimMode

    searchStr = args.strA
    replaceStr = args.strB

    if IsNullOrZeroLen(searchStr):
        body = sys.stdin.read()
        stdinLines = GetLines(body)
        if len(stdinLines) < 2:
            raise "You didn't specified the -a option string. You must specify two lines (first line: old string, second line: new string) from stdin."
        searchStr = stdinLines[0]
        replaceStr = stdinLines[1]

    if trimMode:
        searchStr = StrTrim(searchStr)

    if IsNullOrZeroLen(searchStr):
        raise "Search target string is empty."

    if IsEmptyStr(dst):
        dst = src
    
    hasBom = HasFileBom(src)
    
    with open(src, "rt", encoding="utf_8_sig") as f:
        body = f.read()
        srcLines = GetLines(body)
    
    dstLines = list()

    numReplaced = 0

    for line in srcLines:
        if ignoreCase == False:
            if partialMode == False:
                tmp = line
                if trimMode:
                    tmp = StrTrim(tmp)
                if StrCmp(tmp, searchStr):
                    line = replaceStr
                    numReplaced += 1
            else:
                if SearchStr(line, searchStr, 0, True) != -1:
                    line = ReplaceStr(line, searchStr, replaceStr, True)
                    numReplaced += 1
        else:
            if partialMode == False:
                tmp = line
                if trimMode:
                    tmp = StrTrim(tmp)
                if StrCmpi(tmp, searchStr):
                    line = replaceStr
                    numReplaced += 1
            else:
                if SearchStr(line, searchStr, 0, False) != -1:
                    line = ReplaceStr(line, searchStr, replaceStr, False)
                    numReplaced += 1
        
        dstLines.append(line)

    saveFile = False

    if numReplaced == 0:
        print("No matched string to replace.")
        if dst != src:
            saveFile = True
    else:
        print("Replaced " + str(numReplaced) + " strings.")
        saveFile = True

    encoding = "utf_8"
    if hasBom:
        encoding = "utf_8_sig"

    if saveFile:
        with open(dst, "wt", encoding=encoding) as f:
            for line in dstLines:
                f.write(line + "\n")

    
