import time
import os
CLEAN = '\033[92m'
ENDC = '\033[0m'
def main():
    global old_len
    while True:
        with open("results.txt" ,"r") as info:
            a = info.read()
            print(a)
            time.sleep(1)
            os.system("clear")
            print(CLEAN+"updated"+ENDC)
main()
