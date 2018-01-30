import re;

VERSION = "0.0.1"
BANNER = "WPA Research collection" + VERSION;

def hexToStr(str):
    str = re.sub(r'[^A-Fa-f0-9]', '', str);
    str = str.decode("hex");
    
    return str;
