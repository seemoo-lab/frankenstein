#!/usr/bin/env python3

# Firmware Patch Image (Broadcom) Helper Tool
# Robert Reith, 2021

# 2022/01/06 added firmware unpacking (jiska)

import binascii
import struct
import argparse

class bcolors:
    PINK   = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'
    UNDERLINE = '\033[4m'
    HL = '\033[1m' + '\033[4m' ## HIGHLIGHT

def colorstring(s, c):
    return f"{c}{s}{bcolors.ENDC}"

def crc32(buf):
    return (binascii.crc32(buf) & 0xFFFFFFFF)

def get32bitval(buf, offset=0):
    return struct.unpack('<I', buf[offset:offset+4])[0]

def getbytesFromVal(val):
    return struct.pack('<I', val)

def calc_headercrc(img):
    sectioncount = img[7]
    hcs = 4
    hce = hcs + sectioncount * 0x18 + 0x0c
    return crc32(img[hcs:hce])

def edit_32bit(img, offset, value):
    assert(len(img)>=offset+4)
    img_arr = bytearray(img)
    img_arr[offset:offset+4] = getbytesFromVal(value)
    return img_arr
    
def print_raw_header(img, highlight_offset=-1):
    sectioncount = img[7]
    header_end = sectioncount * 0x18 + 0x10
    lsize = colorstring("SIZE", bcolors.PINK)
    lcrc  = colorstring("CRC", bcolors.RED)
    loff  = colorstring("OFFSET", bcolors.GREEN)
    lmap  = colorstring("MAPTO", bcolors.CYAN)
    ltype  = colorstring("TYPE", bcolors.YELLOW)
    lsc  = colorstring("SCOUNT", bcolors.BLUE)
    print(f"\nCOLOR LEGEND: {ltype} {lsize} {loff} {lmap} {lcrc} {lsc}\n")
    print("           0        4        8        c")
    colorcycle = [bcolors.YELLOW, bcolors.PINK, bcolors.CYAN, bcolors.GREEN, bcolors.RED, bcolors.ENDC]
    index = 0
    for row in range(0, header_end, 16):
        if row == 0:


            r = colorstring("{:08x}".format(get32bitval(img, 0)), bcolors.RED + bcolors.HL * int(highlight_offset == 0))  # CRC
            r += " " + colorstring("{:08x}".format(get32bitval(img, 4)), bcolors.BLUE + bcolors.HL * int(highlight_offset == 4))  # SCOUNT/UNKNOWN
            r += " " + colorstring("{:08x}".format(get32bitval(img, 8)), bcolors.ENDC + bcolors.HL * int(highlight_offset == 8))  # ffffffff
            r += " " + colorstring("{:08x}".format(get32bitval(img, 12)), bcolors.ENDC + bcolors.HL * int(highlight_offset == 12))  # 00000000
        else:
            r = ""
            for i in range(4):
                offset = row + 4 * i
                if offset >= header_end:
                    break
                r += colorstring("{:08x}".format(get32bitval(img, offset)), colorcycle[index] + bcolors.HL * int(offset == highlight_offset))  
                index = (index + 1) % len(colorcycle)
                r += " "


            
        print(f"{row:#010x} {r}")

    if highlight_offset > header_end:
        print("  ***  ")
        r = ""
        row = highlight_offset & 0xfffffff0
        for i in range(4):
            offset = row + 4 * i
            r += colorstring("{:08x}".format(get32bitval(img, offset)), bcolors.ENDC +  bcolors.HL * int(offset == highlight_offset))
            r += " "

        print(f"{row:#010x} {r}")
        # also print the line of our edit




def parse_header(header):
    unknown = header[:0x10]
    headercrc = get32bitval(unknown, offset=0x0)
    val2 = get32bitval(unknown, offset=0x4)

    #print(f"2nd value:   {val2:#010x} ( {val2} Dec)")

    parseme = header[0x10:]
    sections = [
        {
            "name": "header",
            "type": 0,
            "size": 0x100,
            "mapped_to": 0, # 0x218d90 ? not sure if this is always the case
            "start": 0,
            "end": 0x100,
            "crc": headercrc,
            "offset": 0,  # offset for this section def within the header
            "actual_crc" : calc_headercrc(header)
        }
    ]
    count = 0
    offset = 0x10
    while len(parseme) >= 0x18:

        section_type = get32bitval(parseme, offset=0x0)
        if section_type == 0x00000000:
            # section definitions are over
            break
        section_size = get32bitval(parseme, offset=0x4)
        mapped_to = get32bitval(parseme, offset=0x8)
        start = get32bitval(parseme, offset=0xc)
        end = start + section_size
        crc = get32bitval(parseme, offset=0x10)
        #terminator = get32bitval(parseme, offset=0x14)
        if section_type == 0x4:
            name = f"patchram{count}"
            count += 1

        elif section_type == 0x3:
            name = "cfg_meta"

        section = {
            "name": name,
            "type": section_type,
            "size": section_size,
            "mapped_to": mapped_to,
            "start": start,
            "end": end,
            "crc": crc,
            "offset": offset
        }
        sections.append(section)
        parseme = parseme[0x18:]
        offset += 0x18
    return sections

def analyze(img):
    imgsize = len(img)
    assert imgsize > 0x100, "firmware too small"
    header = img[0:0x100]
    sections = parse_header(header)
    for section in sections[1:]:
        sectionimg = img[section["start"]:section["end"]]
        crc = crc32(sectionimg)
        section["actual_crc"] = crc
    return sections
        

def sectionPrinter(sections):
    print("-----------------------------------------------------------------------------------------------------------------")
    print(" NAME      | TYPE       | START      | END        | SIZE       | MAPPED TO  | CRC        | CRC (calc) | MATCHES ")
    print("-----------------------------------------------------------------------------------------------------------------")
    for s in sections:
        sname = s["name"]
        stype = s["type"]
        ssize = s["size"]
        smap = s["mapped_to"]
        sstart = s["start"]
        send = s["end"]
        scrc = s["crc"]
        sacrc = s["actual_crc"]
        match = "Yes" if scrc == sacrc else "No"
        s = f" {sname:<9} | {stype:#010x} | {sstart:#010x} | {send:#010x} | {ssize:#010x} | {smap:#010x} | {scrc:#010x} | {sacrc:#010x} | {match}"
        print(s)
    print("-----------------------------------------------------------------------------------------------------------------")


def fixCRC(img, sections):
    img_arr = bytearray(img)
    fixes = 0
    for s in sections:
        if s["name"] == "header":
            print("Skipping header section")
            continue
        crc = s["crc"]
        actualcrc = s["actual_crc"]
        name = s["name"]
        if crc == actualcrc:
            #print(f"Section {name} CRC is correct")
            continue
        print(f"Section {name} CRC is wrong. Fixing..")
        print(f"Fixing CRC in Section {name}...")
        o = s["offset"] + 0x10
        img_arr = edit_32bit(img_arr, o, actualcrc)
        fixes += 1

    print("All Sections Fixed, fixing header...")
    headercrc = calc_headercrc(img_arr)
    return edit_32bit(img_arr, 0, headercrc)

def add_new_segment(oldimg, newseg_img, newseg_mapto):
    sections = analyze(oldimg)
    newseg_size = len(newseg_img)
    lastseg_start = sections[-1]["start"]
    newseg_newimg = oldimg[0:lastseg_start] + newseg_img + oldimg[lastseg_start:]
    
    seccount = len(sections)  -1
    newsec_headeroffset = 16 + (seccount - 1) * (6*4) 

    newheader = oldimg[0:newsec_headeroffset] + getbytesFromVal(4) +   getbytesFromVal(len(newseg_img)) + getbytesFromVal(newseg_mapto) + getbytesFromVal(lastseg_start) + getbytesFromVal(crc32(newseg_img)) + getbytesFromVal(0) +   oldimg[newsec_headeroffset:newsec_headeroffset + 24]

    newheader =  edit_32bit(newheader, newsec_headeroffset + 36, lastseg_start + newseg_size) # adjust old header mapped to addr

    while len(newheader) < 0x100:
        newheader += getbytesFromVal(0)
    newheader_ssz = get32bitval(newheader, 4) + 0x01000000  # one more segment.
    newheader = edit_32bit(newheader, 4, newheader_ssz)

    newseg_newimg[0:0x100] = newheader[0:0x100]
    headercrc = calc_headercrc(newseg_newimg)
    return edit_32bit(newseg_newimg,0, headercrc)


def main():
    parser = argparse.ArgumentParser(description="Firmware Patch Image (Broadcom) Helper Tool")
    parser.add_argument("filename", help="filename of the Firmware Patch Image that should be analyzed")
    parser.add_argument("--fixcrc", help="fix the crc values in the header", action='store_true')
    parser.add_argument("-e","--edit", help="edit the firmware. takes two 32bit hex values: OFFSET, and VALUE, (with or without 0x). Will not fix CRC, if --fixcrc is not specifically set", nargs=2, metavar=('OFFSET', 'VALUE'))
    parser.add_argument("-p", "--print", help="print raw header", action='store_true')
    parser.add_argument("-t", "--table", help="print header table", action='store_true')
    parser.add_argument("--overwrite", help="overwrite the original file, instead of creating a new one with suffix '.fixed'", action='store_true')
    parser.add_argument("--dryrun", help="don't write any files. Use this with -p and -e to see what the result would look like without writing it to disk", action='store_true')
    parser.add_argument("--newsegment", help="Add a new segment in between the last two segments of the FPI. The segment should be provided as a file containing a binary blob. You also need to provide the address where the segment should be mapped to.", nargs=2, metavar=('MAPTO_ADDR', 'FILENAME'))
    parser.add_argument("-u", "--unpack", help="Unpack firmware image into separate files by address ranges.", action='store_true')

    args = parser.parse_args()

    try:
        img = bytearray(open(args.filename , "rb").read())

    except FileNotFoundError as e:
        print(f"File {args.filename} not found.")
        print(e)
        exit(1)

    # Read the firmware file
    filesize = len(img)
    sectioncount = img[7]
    assert filesize > 7, "Firmware contains no header."
    print(f"File size: {filesize:#010x} Bytes")
    print(f"Number of sections: {sectioncount} ")

    # We have a 100 byte header defining all sections.
    assert filesize > 0x100, "Firmware contains no/empty sections."
    sections = analyze(img)  # this will calc the crc values

    if args.table:
        sectionPrinter(sections)
    
    editflag = False

    if args.edit:
        editoffs = int(args.edit[0], 16)
        editval = int(args.edit[1], 16)
        print(f"Writing {editval:#010x} to offset {editoffs:#010x}")
        img = edit_32bit(img, editoffs, editval)
        editflag = True
        sections = analyze(img)  # recalculate sections

    if args.newsegment:
        newseg_mapto = int(args.newsegment[0], 16)
        newseg_filename= args.newsegment[1]
        try:
            newseg_img = bytearray(open(newseg_filename , "rb").read())
        except FileNotFoundError as e:
            print("ERROR! File not Found!")
            print(e)
            exit(1)
        newseg_segnew = add_new_segment(img, newseg_img, newseg_mapto)
        newfilename = newseg_filename + ".FPI"
        print(f"Writing Changed Firmware Patch Image to {newfilename}")
        open(newfilename, "wb").write(newseg_segnew)
        exit(0)

    if args.fixcrc:
        print("Fixing CRC Values...")
        img = fixCRC(img, sections)
        if len(img) == 0:
            exit(1)
        editflag = True

    if args.print:
        hlo = -1  # highlight offset
        if args.edit:
            hlo = editoffs
        print_raw_header(img, highlight_offset = hlo)

    if editflag:
        if args.dryrun:
            print("DRYRUN. Not writing to disk.")
            exit()
        newfilename = args.filename + ".fixed"
        if args.overwrite:
            newfilename = args.filename
        print(f"Writing Changed Firmware Patch Image to {newfilename}")
        open(newfilename, "wb").write(img)

    if args.unpack:
        print(f"Unpacking {args.filename}...")
        basename = args.filename.replace(".bin", "")
        for section in sections:

            # do not save header
            if section['name'] == 'header':
                continue

            # extract binary contents of section
            sectionfile = f"{basename}.{section['name']}.{section['mapped_to']:#010x}.bin"
            sectionbin = img[section['start']:(section['start'] + section['size'])]
            open(sectionfile, 'wb').write(sectionbin)
            print("  " + sectionfile + " extracted...")

main()
