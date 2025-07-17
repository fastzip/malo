import zlib
import woot

def main():
    while line := input("> "):
        data = woot.compile(line)
        print("data_are", data)
        z = zlib.decompressobj(-15)
        try:
            result = z.decompress(bytes(data))
        except zlib.error as e:
            print(repr(e))
            continue
        print("decompresses_to", result)
        print("unconsumed_tail", z.unconsumed_tail)
        print("unused_data", z.unused_data)
        print("eof", z.eof)

if __name__ == "__main__":
    main()
