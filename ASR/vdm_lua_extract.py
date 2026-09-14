### Original script and research by commial 
### https://github.com/commial/experiments/tree/master/windows-defender
### Set LUADec_Path to binary 
### https://github.com/viruscamp/luadec
import struct
import argparse
import sys
import os
import io
import subprocess
import zlib

LUADec_PATH = "./luadec"

class LuaConst:

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"<{self.__class__} {self.value}>"


class LuaConstNil(LuaConst):
    pass

class LuaConstByte(LuaConst):
    pass

class LuaConstNumber(LuaConst):
    pass

class LuaConstString(LuaConst):
    pass

class LuaFunc:

    def __init__(self, stream):
        self.stream = stream
        self.read_header()
        self.nb_upvalues = self.read_byte()
        self.nb_params = self.read_byte()
        self.is_vararg = self.read_byte()
        self.max_stacksize = self.read_byte()

        self.nb_instr = self.read_int()
        self.instrs = self.stream.read(4 * self.nb_instr)
        self.nb_const = self.read_int()

        self.read_consts()
        self.read_funcs()

        self.read_debug_info()

    def read_header(self):
        src_name = self.stream.read(4)
        assert src_name == b"\x00" * 4
        line_def = self.stream.read(4)
        assert line_def == b"\x00" * 4
        lastline_def = self.stream.read(4)
        assert lastline_def == b"\x00" * 4

    def read_byte(self):
        return struct.unpack("B", self.stream.read(1))[0]

    def read_int(self):
        return struct.unpack("<I", self.stream.read(4))[0]

    def read_consts(self):
        self.consts = []
        for _ in range(self.nb_const):
            cst_type = self.read_byte()
            if cst_type == 4:
                length = self.read_int()
                self.consts.append(LuaConstString(self.stream.read(length)))
            elif cst_type == 3:
                self.consts.append(LuaConstNumber(
                    struct.unpack("<q", self.stream.read(8))[0]))
            elif cst_type == 1:
                self.consts.append(LuaConstByte(self.read_byte()))
            elif cst_type == 0:
                self.consts.append(LuaConstNil(0))
            else:
                raise RuntimeError("Unimplemented")

    def read_funcs(self):
        nb_func = self.read_int()
        self.funcs = [LuaFunc(self.stream) for _ in range(nb_func)]

    def read_debug_info(self):
        src_line_positions = self.read_int()
        assert src_line_positions == 0
        nb_locals = self.read_int()
        assert nb_locals == 0
        nb_upvalues = self.read_int()
        assert nb_upvalues == 0

    def export(self, root=False):
        out = [self.export_header() if root else b""]
        out.extend([b"\x00" * 0x10,
                    struct.pack("BBBB", self.nb_upvalues, self.nb_params,
                                self.is_vararg, self.max_stacksize),
                    struct.pack("<I", self.nb_instr),
                    self.instrs,
                    struct.pack("<I", self.nb_const)])

        for cst in self.consts:
            out.extend(self.export_const(cst))

        out.extend([struct.pack("<I", len(self.funcs))])
        for func in self.funcs:
            out.append(func.export(root=False))
        out
        out.append(struct.pack("<III", 0, 0, 0))
        return b"".join(out)

    def export_header(self):
        return b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00'

    def export_const(self, cst):
        if isinstance(cst, LuaConstNil):
            return [struct.pack("B", 0)]
        elif isinstance(cst, LuaConstByte):
            return [struct.pack("BB", 1, cst.value)]
        elif isinstance(cst, LuaConstNumber):
            return [struct.pack("<B", 3), struct.pack("<d", cst.value)]
        else:
            assert isinstance(cst, LuaConstString)
            return [struct.pack("<BQ", 4, len(cst.value)), cst.value]

def extract_resource_data(input_file):
    data = open(input_file, "rb").read()
    base = data.index(b"RMDX")
    offset, size = struct.unpack("II", data[base + 0x18: base + 0x20])
    x = zlib.decompress(data[base + offset + 8:], -15)
    assert len(x) == size
    output_file = f"{input_file}.extracted"
    open(output_file, "wb").write(x)
    return output_file

def extract_script(fdesc, output):
    header = fdesc.read(12)
    assert header == b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'
    func = LuaFunc(fdesc)
    export = func.export(root=True)
    with open(output, "wb") as f:
        f.write(export)

def process_scripts(options, extracted_file_path):
    os.makedirs(options.output, exist_ok=True)
    data = open(extracted_file_path, "rb").read()
    memstream = io.BytesIO(data)
    loc = 0
    loc = data.find(b'\x1bLuaQ', loc)
    scriptnum = 1
    while (loc != -1):
        memstream.seek(loc, 0)
        try:
            output_path = os.path.join(options.output, f"{scriptnum}.luac")
            extract_script(memstream, output_path)
            if options.decompile:
                decompiled_output_path = os.path.join(options.output, f"{scriptnum}.lua")
                subprocess.run([LUADec_PATH, output_path], stdout=open(decompiled_output_path, "w"))
        except AssertionError as E:
            print("failed assert")
            pass
        loc = data.find(b'\x1bLuaQ', loc+12)
        scriptnum += 1

def main():
    parser = argparse.ArgumentParser("modified VDM MpLua to lua-51 translator")
    parser.add_argument("target", type=argparse.FileType("rb"), help="Target VDM")
    parser.add_argument("output", help="Output folder path")
    parser.add_argument("--decompile", action="store_true", help="Automatically decompile extracted Lua files using luadec")
    options = parser.parse_args()
    
    extracted_file_path = extract_resource_data(options.target.name)
    process_scripts(options, extracted_file_path)

if __name__ == "__main__":
    main()