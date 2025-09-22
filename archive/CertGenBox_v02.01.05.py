#!/usr/bin/env python
"""
CertGenBox with Tkinter GUI (cryptography version)
This file generates various types of digital certificates (CA, server, expired, not-yet-valid, etc.)
and provides a user-friendly Tkinter GUI to configure the generation parameters.
"""

import os, sys, time, threading
import tkinter as tk
import base64
import binascii
from tkinter import ttk, filedialog, scrolledtext, messagebox

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# 导入 Python 标准库的 datetime 模块
import datetime

# === Paste your Base64 encoded PNG string here ===
ICON_PNG_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAR/npUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjapZlXkhzLckT/cxVcQmqxnJRm3AGXz+NZ1YPBANfsXXIaaFEiRQh3jyiz/+e/j/kv/mIu1sRUam45W/5ii813vlT7/PX77my87/cvvqf4/dtx83XCcyjwGZ6fNb/Xf467rwGej8639G2gOt8T4/cT7Z3B1x8DvRMFrcjzZb0DtXeg4J8T7h2gP9uyudXyfQtjP5/rs5P6/Dd6C+WO/TXIz9+xYL2VOBi838EFy3sI7wKC/icTOl/afWdRXJT5Hnl1Tud3JRjkb3b6+mus6OzXFX9e9JtXvr65vx83P70V/XtJ+GHk/PX51+PGpb975Zr+e/zU95v//fh5vxj7w/r6f86q5+6ZXfSYMXV+N/XZyv3GdYMpNHU1LC3bwv/EEOW+Gq9KVE+8tuy0g9d0zXncdVx0y3V33L6f002WGP02vvDF++nDPVhD8c3PIP/Jd9EdX/DqChUvzuv2GPzXWtydttlp7myVmZfjUu8YzHHLv36Zf3vDOUoF52z9shXr8l7GZhnynN65DI+48xo1XQN/Xj//5NeAB5OsrBRpGHY8Q4zkfiFBuI4OXJj4fNLFlfUOgImYOrEYF/AAXnMhuexs8b44hyErDuos3YfoBx5wKfnFIn0MIeOb6jU1txR3L/XJc9hwHDDDE4ksK/iGvMNZMSbip8RKDPUUUkwp5VRSTS31HHLMKedcskCxl1CiKankUkotrfQaaqyp5lpqra325lsANFPLrbTaWuudOTsjd+7uXND78COMOJIZeZRRRxt9Ej4zzjTzLLPONvvyKyzwY+VVVl1t9e02obTjTjvvsutuux9C7QRz4kknn3Lqaad/ee116x+vf+E193rNX0/pwvLlNY6W8hnCCU6SfIbDvIkOjxe5gID28pmtLkYvz8lntnmyInkWmeSz5eQxPBi38+m4j++Mfzwqz/2//GZK/M1v/v/qOSPX/UvP/em3v3ltiYbm9diThTKqDWQfN9buK+6uZwFBDUAZkUVbm3o0LDF28aCu+fbJVr4dAKhj4h8spZ8Mwd1O4zxfkjPPl3xvCn3pYrjPc4wsqs99YmC/7lB2Rg2jb1VztDvmiAmvZf2YtnByzeVaF/1hxbxznUvD30XFZ1FYW1vxbbT+/T7DjfFeG+fSWp5NtQxuhbs80W27+7J3qIoxgBDev9siG5+eJVdCZ/kMNRM9izCabTW31waBdiv5jAUjdz+mG+0E7wbH68LpzDbqNDg4nTjPXhaYP5xNe651ZmhzF7c5kTaINHnP99jqY/WaCPLtgblzRgx7mnE2E+vmg4thHS5l+jMI0+z6OH5sonHqF5Gg6/yA9sJAqKzkepsrzFRMz/Nk4FO2JYJ7XXX7Gn0undhKs5xZFm+EEhPl3HctxGYY22UOOSLwIrzRx2p99ODS9isfoveElsoO2Y0sKyQcMvsmsdoplWBeZ9gCs0Xit+XRgiXX0ooEdd3hjDvnXqxkz5Fm620P9rydjtc4Tt+9jAGHntHTWSX5dOM59RXNHjfmgI/6+s9+/PjxrHud/+XgjAXIkyj7YErcEauZGyuV0RQemTvHLo291TCCRG4k7iTSCtEMxugnq7ZlxtN9aaRp0nrvQOUxVyHL92igXEh7+T0GuLZlubT6yc1hj3IytjmnDSxGZNhFBOWw5ulm4Z2a+plzNJ9GAxaQHO5k15rNzKqxyKMeCltYkx3leCKqokw/tAR/HWckcuQ0MgR62i5dk79efc8FztWUBo4sc8s7rT6pRuZxY44wLTvDY7oLHfz6VAGBV2PcJ2HNesfc2bGpvJ54Sp1wD2PJupk9dsTowM2T/RzwtdUUAE9PzHa3pvuWrHyGj4M/jp2/4MtYct4joV1dKa0xEnjd+wYpAedcRAhrRjcZjlQGDcoknBHPeBUEGslOkLbBtGUnPIfHKixVLyB11wvWBYFPCKekETLpUMeTs6RsP0zQuCiDXbmPtJbpnJENCWzAfGR0Xh8Cosh+d81YaKFNAf4yx1k787Od7fA6MXlcx9qlK2mhEAIdM4L+7ozNQuf4A0ecJ24ns+DAEWrpi8N5DGUR8FuGiSTp3qWTrQmHkeoXTpTsN9VHSCAH8HPAGmnmm3kcFSHiOY5DxXOYBuf7i85EXe2z1jA3412XI4fvbbkBX9jZd60FD8BsNwy8vddxwYWRew2irJAKx7Ird3M7rDrv/CheCOYrLtpvceEv7UBHv0XKt09xelNZFjAoEINzvCIE7Ewg+pPrRYzUCaFtMukeTwPjA8h88HLAFSOJ0ol0llQR65uEbwF9MFIFrQCkePaWEQLATBmwDG4EusvKADGjlzkJuMpkpBfBGBL4jKkTKO6JUrIPEwBB2LZw2dos9aThzKhll8TNa+4G0uHX4wNrfcwPeaZNYC/gbRWHiyojbVAcIFosjmQguUKgpgWCS9/jIIGQCXAIWUxkuV6RUoMob6EOIMCDG5GVELTnKzyIXl8iIsgAMIHMXgiWsYYjvjp3VWkeZqM84m+yZdgZIluxEd7YHmIigoJArt5QMb+4gGTAMBHUQR0dYSG+D79gA1F/0s8AyXhj2jqsITJQAsixgMUW6kESrQgTYf91E7w9MmZLHAi3baCclHao9sqFGzLmEztVN0LfKSlQEJTPF8K/N3a8brAwakxFBEVkkyYJ4BZVETEkLbUG+PPET8F5QHZOacPoniCI5AxRDUEqIoAuiDmRVHWfAWh31MIYeBGErMIRrKL4goqHAGd0KXobC0SPyUQsHf7ZVxsW2Zmr0QWCLLbEfbj/oEQTcVvnDJIMsPIsQF9vhYCyq964iEfQgsMRDkOAxI+BCASzYb24btLis4MTcXyeaAiIcyCRoMlyAP2BUGcklNNG0LJRL3wDAz3jXaoYCV4DURAoS6fcbmdpTl+QFB5vKmgYirOXTzuoueDhbWWECmUB75CVRz2YQ3pdKKtcC1tuUX7H/hmRHhhtx5GRG2zGgUr996t5r5GI283sC13+4s7BV9QEWBOLrknwjbAJRFKCMLgcL+JsD9z1Qy1vybqlAKc43pFr9liktAN8QcNiP0PYX1fey7h6rAfs6ufEM4L5pyH+cRWfE/Fh9faALUybxkCbB+XcEHAxGpGDzECnB0d9kgJ4NJBYyzak4CPc65esao4EyMWIVdKLpZ3qJ0WQLA8pcomh06hySDoAcwlgtjAmPKTIUvgVSZbqtgnDVUIlbN+t0j81EjsS6IWyMnqyRV8bcLyi5OEAQddCjO2HfUHTLPY1uJshoKg2r17H6U1UkdGG3JNVQksskwsNLl6zFAVRcglja0WUW6j6Y1Z6CInEY0JQDtRe44ghmOwMJwyKjI5IAGWcyizw3RY06I5gGBXTBmKM34I4ZDGjEtaUkSNhfFFiehOnccuCPRa4hNQQK8PqCVI/feW6M7QQDdJpKD3akx+HdAXEqbdQMx4DAgzQQLTojCfzom145g4CglNlHumbbsAobMW84SkistZA2Wu5ihUki/KELDQCEwDauVspPk4hMI60JRZUr1Yy0EsNheCeEcEbnSowIxSScnd43IvQOwIIrCPxo0IoimEyuTyTN6rH3I2pFoSxRNP8Ta49SxcvuxtWKCZ7YRb1dBDGYBTgkQwwO5/fDc9iqhikJnBjIvuJK4T80agkAJo5VsoeCn1ejR/LqRrFreJ+BiSOOlPnq19juZXWFclL1ZlNDcBIsaFJIJGudgKsQJHjUum+R2Jgm0UCbiZ9vA/Wh1DhMIAdEkUtF9HzYBUSiEfo3MA56TVsBbr1Y3efjjhCOYPjVK3SltlznlQiRZqiH69Qm1As8SpID/CXI7NtT3VBvPjOGQRNJtd2UTXRsSnBRvyQRJCMIhvjAYeF8oq8prLejVIRsFRJghJC5CJTWfXqM1iD+rw1GUhMDXxUvqEJgGG4Qi0KssFJPHexNEgMm/GLECJ5VNotz4x7jcsi/kqirHJa4N8bpAH5EY0UMBtIogiu5wlYPEXFCxnpDlLmsJCBykREEPCSlpalx5jqJWEcM/IVWzh3gU1j1m0zcKS2+X4IgHTDBOVBTpP85Qty4Nyiya0XmblLSJRQzye5OUkBT+Gnannc4LhjoNbmoLbrKH9kuso5dP6S/AKrqNkIxIKAhrbZVVCRjuQeB3OAS7lpW+ouMIz1HitnAylMj/EoHkkxR8Z4ajEkgM+qsrIjDSM0ldTwifiUCifVB7kRP/Ujg02wYASyiKoIUZZFjPBiKkR+3S1J0AxqL/xwE5YaEtCJVGtxDW3ae1ZHwhiZIG6r9wQAga+cony2lMpMaR2lBtjXL2t4dV86eAl3JDuUY5m4QKd6FFunkoRnutoqlEa1djXCFDTkqPIXdU49zSBXtlJHXI64K7CURqTbjhg7qruDistaI8ppgYOUkqqnbrwB08JwsJtRZpeog4HmLZU6ygxrTiDZlCjIEUTradYn7/EV4UnBfvsMxBj3Q3lNwcA4eSs4nh5ZBrJ99GaQMM7CC0jboTjQgJn0nGr+HOTnDWGYiyxB+/b5NFsUNSAbC4dgCBrAXxwDf6kPQlF6WFO4mxyHwpuqskjN1kXYBp2jVrpFn3NgL/q2Ev+tN6M6EDKehAy2HoQ2skaFcy/Q0vpL2bS8JPVtG+ZNlDh1N5qpdgLdW+fkbA4jHt5G2q9ivAu2lyp2ZAXV1+2Y3gCpYFhDcZiifK+rIwbVRD3nbVNQ18pXMr9SnGoHnrYJb+G5uAhvoDvoaUtRqZQNMB0fIL3eUpU9n85Y2ShJboHgmhCW5AOBQXpiKF3/BYavG8fumcxTTBFDK/MFcQ+qEP7pUR5dBHOVR3mVx+O/LDUubAMLh74dg3i75yWbweLzaMoRb5WPPwrFdXmbB+Fq+RHsqJBewnsz6VkQ8N708ABERfUez7vyUGa5jRYWpryfy9YmF5NuF5gRDiCY2yAe/KY+7EwRr+HTFHq3AGT9o/f7H38a9X+sKqPbsn16bCHC0KxAaOQ+HZLxdkjK0yEhE2tmxRjdhaaBSDpibNzmKFX2uM3RozJwO/m+XYGPa2vWIzIFuvyaYsgwGqUSiYQONkvFB3CDe49an7VixoMFYlL7B5Xi1al7esygDckjCUFE4U8F0KHQQOabMojqDLuLS53mwq41j6Ls5OPNTcqnpNykVFcVksF1OSzPAPD4470h6IovYFvQ/Nr62k9zoKtWE+XK9VQ+B/nQH/9lwC0JHK9qIinxGug8yWk8eb0NrqvN1JsV1oK8VKAwmz1frfCa36757Xnnj9vMX/zZ/HNFVFNfz9mrVBYltP9qtTfOTK+RZr1x34yQh+XoOQZxCkPsQ5ap72MFVDfv2M2QzFDPAUWE3iPac3YoxqkOrh6pGJFYXt5qIarZqWfm7c42PZ2gSlZbQd0HZdVUdodPs4v4SBeiV3X1KUUFH/PpKFDNoSCJKz3gcSnHqU4obqLQC1Pdh3ZLPpL61kWw8q2hjJsfrh+E9W1oomem2GNSwLa/TIRT5x2kfzuuXi2C2lf1PHE6DAb9cKZeFKCyK99KPoSj+s/njqyCtNzVsQW4/0iijnmLtdgKxVp3uH+T/Rmqoqq4HINQJdM11fO4o7n8C8ZbdKb7J2HlajW/xZPv05BPo7x9Ho+sEDXwCmB2rpAslHeuzXc3t8kI6TjRD6EY/W08oksp59WSySxxJgnNp+gITyFBgJDKIU89+6ZeAWqpZoUJ93yqtoXnerCDo/e9rZ+H78VoUB9vTxZdaKSAgyo81LHVcbxFVsVnBIQgqdn1UM+H2W4H6SkKpPH1DXzhZur+pj6i/uuZyI/HB/Y2GX878OOz6enQVgKaBskBG1QDYB2qf6tx5ghsKRrgE7Fr1SNXle0fmdMxl3RKU8OmXNXesBEakZukxhzIiPJRf5pIQobo4c4VFR1Ac4i+nob61VefApX9DlPvZYYbqGL9oXjwGuFL4n2G+0zLWq2uCldh3TIczmHqA2uQ/eXV1VAjuemouLX8liCWQ71HEH9JwxLYcpcOiep0BolAxG+96tDURx5KG3oqsD/ER30aDtb+4+fzzM5YN/S0Lwn2rk4hsKmJIxpDj2vVCaWanRIolBqh3DMIV9KBGM4fVWONVI0kkbx8NYoG2jrPz3eCbwsIalqa/wVcL+q2ZelKEgAAAYRpQ0NQSUNDIHByb2ZpbGUAAHicfZE9SMNAHMVfU7UqFQc7iDhkqOJgQVTEUapYBAulrdCqg8mlX9CkIUlxcRRcCw5+LFYdXJx1dXAVBMEPEHfBSdFFSvxfUmgR48FxP97de9y9A4R6malmxwSgapaRjEXFTHZVDLyiB350YQwBiZl6PLWYhuf4uoePr3cRnuV97s/Rp+RMBvhE4jmmGxbxBvHMpqVz3icOsaKkEJ8Tjxt0QeJHrssuv3EuOCzwzJCRTs4Th4jFQhvLbcyKhko8TRxWVI3yhYzLCuctzmq5ypr35C8M5rSVFNdpDiOGJcSRgAgZVZRQhoUIrRopJpK0H/XwDzn+BLlkcpXAyLGAClRIjh/8D353a+anJt2kYBTofLHtjxEgsAs0arb9fWzbjRPA/wxcaS1/pQ7MfpJea2nhI6B/G7i4bmnyHnC5Aww+6ZIhOZKfppDPA+9n9E1ZYOAW6F1ze2vu4/QBSFNXyzfAwSEwWqDsdY93d7f39u+ZZn8/OVJykLrouiQAABAfaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8P3hwYWNrZXQgYmVnaW49Iu+7vyIgaWQ9Ilc1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCI/Pgo8eDp4bXBtZXRhIHhtbG5zOng9ImFkb2JlOm5zOm1ldGEvIiB4OnhtcHRrPSJYTVAgQ29yZSA0LjQuMC1FeGl2MiI+CiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIKICAgIHhtbG5zOnN0RXZ0PSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOkdJTVA9Imh0dHA6Ly93d3cuZ2ltcC5vcmcveG1wLyIKICAgIHhtbG5zOmlwdGNFeHQ9Imh0dHA6Ly9pcHRjLm9yZy9zdGQvSXB0YzR4bXBFeHQvMjAwOC0wMi0yOS8iCiAgICB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOmE4MzRhNmI1LWQyMDAtNGEzZC05NWZmLTI2ODlkNzIzOTlkMCIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDphNDczZjIyNy02MTAwLTQ3NTAtOGI4OC00NDUyMzkyOWQxOWMiCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDoxZTkwM2UyNy1jZmMwLTQ4NzAtYjE0Mi1mZTI4MjczMTQ3YTAiCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBleGlmOkRhdGVUaW1lT3JpZ2luYWw9IjIwMjUtMDktMDNUMDY6Mzk6MTArMDA6MDAiCiAgIEdJTVA6QVBJPSIyLjAiCiAgIEdJTVA6UGxhdGZvcm09IldpbmRvd3MiCiAgIEdJTVA6VGltZVN0YW1wPSIxNzU2ODgxODY3NzE2MTExIgogICBHSU1QOlZlcnNpb249IjIuMTAuMzAiCiAgIGlwdGNFeHQ6RGlnaXRhbFNvdXJjZUZpbGVUeXBlPSJodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL2NvbXBvc2l0ZVdpdGhUcmFpbmVkQWxnb3JpdGhtaWNNZWRpYSIKICAgaXB0Y0V4dDpEaWdpdGFsU291cmNlVHlwZT0iaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9jb21wb3NpdGVXaXRoVHJhaW5lZEFsZ29yaXRobWljTWVkaWEiCiAgIHBob3Rvc2hvcDpDcmVkaXQ9IkVkaXRlZCB3aXRoIEdvb2dsZSBBSSIKICAgcGhvdG9zaG9wOkRhdGVDcmVhdGVkPSIyMDI1LTA5LTAzVDA2OjM5OjEwKzAwOjAwIgogICB0aWZmOk9yaWVudGF0aW9uPSIxIgogICB4bXA6Q3JlYXRvclRvb2w9IkdJTVAgMi4xMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjllMmQxYTUwLTcyMWEtNDU1MC05Y2RkLTA2ZmM0ZDJiYTQ3OCIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyNS0wOS0wM1QxNjo0MjoyNCIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDpkZmMxZjVmOC00NTIxLTQ5YzMtODA0YS03ODMzYzY4NThhMTkiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjUtMDktMDNUMTY6NDQ6MjciLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg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
"""

DEFAULT_KEYSIZE = 2048
DEFAULT_HASH = 'sha256'
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
DEFAULT_COMMON_NAME = "example.com"
DEFAULT_EMAIL = "admin@example.com"
DEFAULT_CERT_COUNT = 5 

HASH_ALGORITHMS = {
    'sha1': hashes.SHA1(),
    'sha224': hashes.SHA224(),
    'sha256': hashes.SHA256(),
    'sha384': hashes.SHA384(),
    'sha512': hashes.SHA512(),
    'md5': hashes.MD5(),
}

def ensure_path(path):
    try:
        os.makedirs(path, exist_ok=True)
        return True, f"Directory '{path}' ready." 
    except Exception as e:
        return False, str(e)

def save_cert_and_key(cert, key, cert_path, key_path):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def mkcert(subject_name, issuer_name=None, issuer_key=None, key=None, sign_alg='sha256',
           not_before=None, not_after=None, serial=1, is_ca=False, key_size=2048):
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if not_before is None:
        not_before = datetime.datetime.utcnow()
    if not_after is None:
        not_after = not_before + datetime.timedelta(days=365*5)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_name.get('C','AU')),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_name.get('ST', 'Victoria')),
        x509.NameAttribute(NameOID.LOCALITY_NAME, subject_name.get('L', 'Melbourne')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name.get('O', 'CertGenBox')),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name.get('CN','TEST')),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_name.get('Email','demo@example.com')),
    ])

    if issuer_name is None:
        issuer_name = subject

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    if issuer_key is None:
        issuer_key = key

    cert = builder.sign(private_key=issuer_key, algorithm=HASH_ALGORITHMS[sign_alg], backend=default_backend())

    return cert, key

def generate_all(output_path, log_cb=print, keysize=2048, sign_alg='sha256', ca_cn="TESTCA", ca_email="demo@example.com", cert_count=DEFAULT_CERT_COUNT):
    ok, msg = ensure_path(output_path)
    log_cb(msg)

    serial = 1000

    # 1. 生成 CA 证书、私钥和公钥
    log_cb("Generating CA certificate")
    ca_subject = {"C":"AU","CN":ca_cn,"Email":ca_email}
    ca_cert, ca_key = mkcert(ca_subject, serial=serial, is_ca=True, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(ca_cert, ca_key, os.path.join(output_path,"ca-cert.pem"), os.path.join(output_path,"ca-cert.key"))
    serial += 1

    # 2. 生成 server-cert 证书、私钥和公钥，并由 CA 签名
    log_cb("Generating server certificate signed by CA")
    server_subject = {"C":"AU","CN":"server","Email":ca_email}
    server_cert, server_key = mkcert(server_subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(server_cert, server_key, os.path.join(output_path,"server-cert.pem"), os.path.join(output_path,"server-cert.key"))
    serial += 1

    # 3. 生成 device-cert 证书、私钥和公钥，并由 CA 签名
    log_cb("Generating device certificate signed by CA")
    device_subject = {"C":"AU","CN":"device","Email":ca_email}
    device_cert, device_key = mkcert(device_subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(device_cert, device_key, os.path.join(output_path,"device-cert.pem"), os.path.join(output_path,"device-cert.key"))
    serial += 1
    
    # 生成指定数量的普通证书
    log_cb(f"Generating {cert_count} regular certificates signed by CA")
    for i in range(cert_count):
        subject = {"CN": f"{ca_cn}-cert-{i:02d}", "Email": f"cert-{i:02d}@{ca_email.split('@')[-1]}"}
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg)
        save_cert_and_key(cert, key, os.path.join(output_path, f"regular-cert-{i:02d}.pem"), os.path.join(output_path, f"regular-cert-{i:02d}.key"))
        serial += 1

    # 生成过期证书
    log_cb("Generating expired certificates")
    for i in range(cert_count):
        subject = {"CN": f"expired-cert-{i:02d}", "Email": f"expired-{i:02d}@{ca_email.split('@')[-1]}"}
        not_before = datetime.datetime.utcnow() - datetime.timedelta(days=730)
        not_after = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
        save_cert_and_key(cert, key, os.path.join(output_path, f"expired-cert-{i:02d}.pem"), os.path.join(output_path, f"expired-cert-{i:02d}.key"))
        serial += 1

    # 生成尚未生效的证书
    log_cb("Generating not-yet-valid certificates")
    for i in range(cert_count):
        subject = {"CN": f"future-cert-{i:02d}", "Email": f"future-{i:02d}@{ca_email.split('@')[-1]}"}
        not_before = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        not_after = not_before + datetime.timedelta(days=365)
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
        save_cert_and_key(cert, key, os.path.join(output_path, f"future-cert-{i:02d}.pem"), os.path.join(output_path, f"future-cert-{i:02d}.key"))
        serial += 1
    
    log_cb("Certificate generation finished.")

class CertGenGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        ver = "v02.01.04"
        yr = "2025.09.22"
        self.title('CertGenBox - ' + 'Nigel Zhai - ' + ver + ' - ' + yr)
        self.geometry('500x550')
        self.create_widgets()

        # Set the window icon
        self.set_window_icon()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # 调整：将所有参数放在一个 LabelFrame 中
        params_frame = ttk.LabelFrame(frm, text="Cert Parameters", padding=10)
        params_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        # Key Size and Signature Algorithm
        ttk.Label(params_frame, text='Key size:').grid(row=0, column=0, sticky='w')
        self.keysize_var = tk.IntVar(value=DEFAULT_KEYSIZE)
        ttk.Entry(params_frame, textvariable=self.keysize_var, width=10).grid(row=1, column=0, sticky='w')

        ttk.Label(params_frame, text='Signature algorithm:').grid(row=0, column=1, sticky='w', padx=(10,0))
        self.signalg_var = tk.StringVar(value=DEFAULT_HASH)
        ttk.Combobox(params_frame, textvariable=self.signalg_var, values=list(HASH_ALGORITHMS.keys()), width=12).grid(row=1, column=1, sticky='w', padx=(10,0))

        # Certificate Count
        ttk.Label(params_frame, text='Number of certs to generate (per type):').grid(row=2, column=0, sticky='w', pady=(8,0))
        self.cert_count_var = tk.IntVar(value=DEFAULT_CERT_COUNT)
        ttk.Entry(params_frame, textvariable=self.cert_count_var, width=10).grid(row=3, column=0, sticky='w')

        # CA Fields
        ttk.Label(params_frame, text='CA Common Name:').grid(row=4, column=0, sticky='w', pady=(8,0))
        self.ca_cn_var = tk.StringVar(value="TESTCA")
        ttk.Entry(params_frame, textvariable=self.ca_cn_var, width=30).grid(row=5, column=0, sticky='w')

        ttk.Label(params_frame, text='CA Email:').grid(row=4, column=1, sticky='w', padx=(10,0), pady=(8,0))
        self.ca_email_var = tk.StringVar(value="demo@example.com")
        ttk.Entry(params_frame, textvariable=self.ca_email_var, width=30).grid(row=5, column=1, sticky='w', padx=(10,0))

        # 调整：创建按钮区域，并放在顶部
        button_frame = ttk.Frame(frm)
        button_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 5))

        # Output Path
        ttk.Label(button_frame, text='Output directory:').grid(row=0, column=0, sticky='w', padx=5, pady=0)
        self.path_var = tk.StringVar(value=DEFAULT_PATH)
        ttk.Entry(button_frame, textvariable=self.path_var, width=55).grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Button(button_frame, text='Browse...', command=self.browse_path).grid(row=1, column=1, sticky='w', padx=5, pady=5)

        # 调整：将 "Run Generation" 和 "Open Output Folder" 放在同一行
        action_button_frame = ttk.Frame(frm)
        action_button_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))
        ttk.Button(action_button_frame, text='Run Generation', command=self.on_run).grid(row=2, column=0, padx=5, sticky='E')
        ttk.Button(action_button_frame, text='Open Output Folder', command=self.open_output).grid(row=2, column=1, padx=5, sticky='E')

        # Log
        ttk.Label(frm, text='Log:').pack(anchor='w', pady=(10,0))
        self.logbox = scrolledtext.ScrolledText(frm, state='disabled', wrap=tk.WORD, width=90, height=20)
        self.logbox.pack(fill=tk.BOTH, expand=True)

    def set_window_icon(self):
        try:
            # Decode the Base64 string
            icon_data = base64.b64decode(ICON_PNG_BASE64)

            # Attempt to use PhotoImage directly
            try:
                photo_image = tk.PhotoImage(data=icon_data)
                self.master.iconphoto(True, photo_image)
            except tk.TclError:
                # Fallback to .ico if PhotoImage fails (e.g., if the data isn't a valid PNG or Tkinter version issues)
                # This requires writing to a temporary .ico file.
                print("PhotoImage failed, attempting .ico fallback...")
                temp_ico_path = os.path.join(tempfile.gettempdir(), "temp_icon.ico")
                with open(temp_ico_path, "wb") as f:
                    f.write(icon_data) # Assuming the base64 could also be an ICO
                self.master.iconbitmap(temp_ico_path)
                os.remove(temp_ico_path) # Clean up the temporary file

        except Exception as e:
            print(f"Error setting PNG icon from Base64 or ICO fallback: \n{e}")
            print("Ensure the Base64 string is correct and represents a valid PNG or ICO image.")
            # Fallback to a default Tkinter icon if all else fails
            self.master.iconbitmap(default="::tk::icons::question")

    def browse_path(self):
        p = filedialog.askdirectory(initialdir='.', title='Select output directory')
        if p:
            self.path_var.set(p)

    def open_output(self):
        p = os.path.abspath(self.path_var.get())
        if os.path.isdir(p):
            if sys.platform.startswith('win'):
                os.startfile(p)
            elif sys.platform.startswith('darwin'):
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        else:
            messagebox.showerror('Error','Output directory does not exist')

    def log(self, msg):
        self.logbox.configure(state='normal')
        self.logbox.insert(tk.END, str(msg) + '\n')
        self.logbox.see(tk.END)
        self.logbox.configure(state='disabled')
        print(msg)

    def on_run(self):
        out = self.path_var.get() or DEFAULT_PATH
        try:
            keysize = int(self.keysize_var.get())
            cert_count = int(self.cert_count_var.get())
            if keysize < 1024 or keysize > 4096:
                raise ValueError("Key size must be between 1024 and 4096 bits.")
            if cert_count < 1 or cert_count > 100:
                raise ValueError("Certificate count must be between 1 and 100.")
        except ValueError as e:
            messagebox.showerror('Input Error', str(e))
            return
            
        signalg = self.signalg_var.get()
        ca_cn = self.ca_cn_var.get()
        ca_email = self.ca_email_var.get()

        t = threading.Thread(target=self._run_thread, args=(out, keysize, signalg, ca_cn, ca_email, cert_count), daemon=True)
        t.start()

    def _run_thread(self, out, keysize, signalg, ca_cn, ca_email, cert_count):
        try:
            self.log(f'Starting generation into: {out}')
            self.log(f'Parameters: KeySize={keysize}, SignAlg={signalg}, CA_CN={ca_cn}, CertCount={cert_count}')
            generate_all(out, log_cb=self.log, keysize=keysize, sign_alg=signalg, ca_cn=ca_cn, ca_email=ca_email, cert_count=cert_count)
            self.log('Done')
            messagebox.showinfo('Finished','Certificate generation finished. See log for details.')
        except Exception as e:
            self.log(f'Error during generation: {e}')
            messagebox.showerror('Error', f'Generation failed: {e}')

if __name__ == '__main__':
    app = CertGenGUI()
    app.mainloop()