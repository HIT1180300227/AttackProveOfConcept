This repository contains a poc of attack strategies for vmess protocol vulnerabilities metioned in https://github.com/v2ray/v2ray-core/issues/2523

attackpoc.go completes the use of the vulnerability mentioned in the issue above, and uses local related configuration information to obtain the original data', including 'version number', 'data encryption IV', 
'data encryption key', 'response authentication V', ''encryption Mode Sec' and other information
