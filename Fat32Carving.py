from struct import *
import sys
import math
import win32api

p2 = lambda x, y : pack_from('<H', x, y)
up1 = lambda x, y : unpack_from('@c', x, y)[0]
up2 = lambda x, y : unpack_from('<H', x, y)[0]
r_up2 = lambda x, y : unpack_from('>H', x, y)[0]
up4 = lambda x, y : unpack_from('<L', x, y)[0]
r_up4 = lambda x, y : unpack_from('>L', x, y)[0]
uc_up1 = lambda x, y : unpack_from('B', x, y)[0]

def main():
    drivename = input("[*] Input Drive Name : ")
    
    if is_exist_drive(drivename):
        global drive_path, drive_data
        drive_path = "\\\\.\\"+drivename+":"
        drive_data = open(drive_path, 'rb')
        read_bootsector()
        read_filesysteminfo()
        read_fatarea()
        print("\n[*] Start Carving..................")
        crawling_Freecluster()
        print("\n[*] Finish Carving.................")
    else:
        print("\n\n[*] Program terminated....")
        exit(1)

        
def is_exist_drive(drivename):
    try:
        path = drivename+":\\\\"
        drive_info = win32api.GetVolumeInformation(path)
        if is_fat32(drive_info[4]):
            
            return 1
        else:
            print("[*] This Drive is not FAT32")
            return 0
    except:
        print("[*] NonExisted Drive")
        return 0
def is_fat32(drivetype):
    if drivetype == "FAT32":
        return 1
    else:
        return 0
def calc_size_sector(sector):
    return sector * bytesPSector
def calc_size_cluster():
    global sizeOfCluster
    sizeOfCluster = bytesPSector * secPCluster
def calc_offset_dataarea():
    global offsetDataarea

    offsetDataarea = (reservedSector + (FatSize * 2))
def get_offset_cluster(n):

    numClutser = n - 2
    if numClutser < 0 :
        print("\n [*] This Cluster Number is out of bound")
        return -1;
    else:
        offsetCluster = calc_size_sector(offsetDataarea) + (sizeOfCluster * numClutser)
        return offsetCluster

def read_bootsector():
    global bytesPSector, FatSize, reservedSector, secPCluster
    drive_data.seek(0)
    bootsc = drive_data.read(512)
    bytesPSector = up2(bootsc, 0xb)
    secPCluster = uc_up1(bootsc, 0xd)
    reservedSector = up2(bootsc,0xe)
    FatNum = uc_up1(bootsc, 0x10)
    mediaType = uc_up1(bootsc, 0x15)
    FatSize = up4(bootsc, 0x24)
    RootDirClusterOffset = up4(bootsc, 0x2c)
    FSinfoOffset = up2(bootsc, 0x30)
    VLabel = unpack_from('<10s',bootsc,0x47)[0]
    FStype = unpack_from('<8s',bootsc,0x52)[0]
    magic = r_up2(bootsc,0x1fe)

    print ("\n[+] BootSector Info\t\t\t================")
    print ("[+] Bytes per Sector:\t\t\t", bytesPSector)
    print ("[+] Sectors per Cluster:\t\t", secPCluster)
    print ("[+] Reserved Sector Count:\t\t", reservedSector)
    print ("[+] Number of FAT:\t\t\t", FatNum)
    print ("[+] Media Type:\t\t\t\t", hex(mediaType))
    print ("[+] RootDirClusterOffset:\t\t", RootDirClusterOffset)
    print ("[+] Size of FAT:\t\t\t", FatSize)
    print ("[+] FSInfo Offset:\t\t\t", FSinfoOffset)
    print ("[+] Volume Label:\t\t\t", VLabel)
    print ("[+] FileSystem Type:\t\t\t", FStype)
    print ("[+] Signature:\t\t\t\t", hex(magic))

    calc_size_cluster()
    calc_offset_dataarea()

def read_filesysteminfo():
    global nextFreeCluster, numFreeCluster
    filesysinfo = drive_data.read(512)

    magic = up4(filesysinfo, 0x00)
    magic2 = up4(filesysinfo, 0x1E4)
    numFreeCluster = up4(filesysinfo, 0x1E8)
    nextFreeCluster = up4(filesysinfo, 0x1EC)
    magic3 = r_up2(filesysinfo, 0x1FE)

    print("\n[*] File System Information\t\t================")
    print("[*] Head Signature:\t\t\t", hex(magic))
    print("[*] Signature2:\t\t\t\t", hex(magic2))
    print("[*] Number of Free Cluster:\t\t", numFreeCluster)
    print("[*] Next Free Cluster:\t\t\t", nextFreeCluster)
    print("[*] Tail Signature:\t\t\t", hex(magic3))
    
def read_fatarea():
    print(calc_size_sector(reservedSector))
    drive_data.seek(calc_size_sector(reservedSector))
    fatarea = drive_data.read(8)

    mediaType = up4(fatarea, 0x00)
    partitionStatus = up4(fatarea, 0x04)

    print ("\n[*] File Allocation Table\t\t================")
    print ("[*] Media Type:\t\t\t\t", hex(mediaType))
    print ("[*] Partition Status:\t\t\t", hex(partitionStatus))


def crawling_Freecluster():

    numcluster = nextFreeCluster
    targetEntry = 0x04 * numcluster
    comparison_sizeFat = calc_size_sector(FatSize)-4

    drive_data.seek(calc_size_sector(reservedSector))
    target_fatarea = drive_data.read(calc_size_sector(FatSize))
    i = 0
    while True:
        index_comparison = up4(target_fatarea, targetEntry) ##24, 28, 32, 36....

        if index_comparison == 0:
            i = i + 1
            offset_cluster = get_offset_cluster(numcluster)
            drive_data.seek(offset_cluster)
            cluster = drive_data.read(16)
            if up4(cluster, 0) != 0:
                numSignature = analysis_signature(hex(r_up4(cluster, 0)))
                if int(numSignature) > 0 :
                    ext = print_signature(numSignature, cluster, offset_cluster)
                    print("[*] ", numcluster, " - ", ext)
                    if ext == "zip" :
                        analysis_zip(offset_cluster)
                   

        if i == numFreeCluster:
            break
        else:
            numcluster = numcluster + 1
            targetEntry = 0x04 * numcluster 

def analysis_signature(sig):
    
    if sig == "0x504b0304" or sig == "0x504b4c49":##zip//docx
        return 1
    elif sig == "0x57696e5a":##winzip
        return 2
    elif sig == "0x25504446":##pdf
        return 3
    elif sig == "0xffd8ffe0" or sig == "0xffd8ffe1" or sig == "ffd8ffe8":##jpeg
        return 4
    elif sig == "0x89504e47":##png
        return 5
    elif sig == "0xf00e803":##ppt
        return 6
    elif sig == "0xd0cf11e0":##hwp
        return 7
    elif sig == "0x4d5a0000":##pe
        return 8
    else:
        return 0

def print_signature(ret, sig, offset):
    if ret == 1 or ret == 2 :##zip
        return analysis_detail(1, sig, offset)
    elif ret == 2:##winzip
        return "zip"
    elif ret == 3:##pdf
        return "pdf"
    elif ret == 4:##jpeg
        return "jpg"
    elif ret == 5:##png
        return "png"
    elif ret == 6:##ppt
        return "ppt"
    elif ret == 8:##hwp
        return "hwp"
    elif ret == 9:##pe
        return "PE FILE"
    else:
        return 0

def analysis_detail(ret, sig, offset):
    tail = hex(r_up4(sig, 4))
    if ret == 1:
        if tail == "0x14000600":
            drive_data.seek(offset)
            zip_data = drive_data.read(sizeOfCluster)

            if zip_data.hex().find("776f7264") != -1:
                return "docx"
            elif zip_data.hex().find("786c") != -1:
                return "xlsx"
            elif zip_data.hex().find("707074") != -1:
                return "pptx"
        else:
            return "zip"
    
def analysis_zip(offset_zipdata):
    print("[*]\t Start Unzip..........")
    drive_data.seek(offset_zipdata)
    zipdata = drive_data.read(sizeOfCluster)
    offsetFile = 0
    headersize = 30
    while True:
        sig = hex(r_up4(zipdata, 0x00+offsetFile))
        if sig == "0x504b0304":
            filesize = up4(zipdata, 0x12+offsetFile)
            filenamelen = up2(zipdata, 0x1A+offsetFile)
            param = ">"+str(filenamelen)+"s"
        
            print("|\t\t",unpack_from(param, zipdata, 0x1E+offsetFile)[0].decode("utf-8"))
            offsetFile = offsetFile+headersize+filesize+filenamelen
            if offsetFile >= sizeOfCluster:
                break
        else:
        
            break
        
    print("[*]\t Finish Unzip..........")
if __name__ == "__main__":
    main()