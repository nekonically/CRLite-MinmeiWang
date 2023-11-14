import base64
import binascii
from typing import List, Tuple, Optional
import os

#Referenced https://github.com/mozilla/crlite

#JUNBEOM IN - 2023
#
#키
#
def crlite_key(issuer, serial):
    # Issue,Serial 합쳐서 Return
    return issuer + serial

#   파일 읽어서 String으로 던지기
def read_file_by_lines(path):
    with open(path, 'r') as file:
        return file.readlines()
# Issuer 디코딩 (Base 64 -> bytes)
def decode_issuer(param):
    return base64.urlsafe_b64decode(param)
#  Serial 가지고 오기
def decode_serial(param):
    # Hex String 디코딩 -> Bytes
    return bytes.fromhex(param)



def list_issuer_file_pairs(revokedDir, knownDir) -> List[Tuple[bytes, Optional[str], str]]:
    # 파일이름 전부다 불러오기
    known_issuers = [filename for filename in os.listdir(knownDir)]

    pairs = []
    for issuer in known_issuers:
        k_file = os.path.join(knownDir, issuer)
        r_file = os.path.join(revokedDir, issuer)
        issuer_bytes = decode_issuer(issuer.encode())

        # Check if corresponding file exists in revoked directory
        if os.path.exists(r_file):
            pairs.append((issuer_bytes, r_file, k_file))
        else:
            pairs.append((issuer_bytes, None, k_file))

    return pairs





def create_cascade(out_file, revoked_dir, known_dir, hash_alg):
    print("1. Serial 세는중")
    revoked, not_revoked = count_all(revoked_dir, known_dir)

    print(f"2. Revoked :  {revoked}")
    print(f"2. Not Revoked :  {not_revoked}")


    salt = os.urandom(salt_len)

    builder = CascadeBuilder(hash_alg, salt, revoked, not_revoked)

    print("3. Revoked 된 Serial 처리")
    include_all(builder, revoked_dir, known_dir)

    print("4. Non-Revoked (Normal) Serial 처리")
    exclude_all(builder, revoked_dir, known_dir)

    print("5. FP-False Positive 제거하기")
    cascade = builder.finalize()

    print("6. 병렬화(Serialization) 체크")
    cascade_bytes = cascade.to_bytes()  # Handle exceptions as needed
    print(f"6. {len(cascade_bytes)} bytes")

    #만약에 cascade 맞는 경우
    if cascade:
        print("7. Cascade 확인됨")
        print(f"7. \n{cascade}")

        check_all(cascade, revoked_dir, known_dir)

        print("8. Cascade 파일작성")
        with open(out_file, 'wb') as filter_writer:
            filter_writer.write(cascade_bytes)
    else:
        raise Exception("ERROR) Cascade 비어있음")

def main():

    known_dir = Path(args.known)
    revoked_dir = Path(args.revoked)
    prev_revset_file = Path(args.prev_revset) if args.prev_revset else None
    out_dir = Path(args.outdir)

    filter_file = out_dir / "filter"
    stash_file = out_dir / "filter.stash"
    revset_file = out_dir / "revset.bin"



    # Call custom functions
    print("Generating cascade")
    create_cascade(filter_file, revoked_dir, known_dir, hash_alg)

    print("Generating stash file")
    write_revset_and_stash(revset_file, stash_file, prev_revset_file, revoked_dir, known_dir)

    print("Done")

if __name__ == "__main__":
    main()