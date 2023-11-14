import datetime
import hashlib
import math
import random
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.x509.oid import NameOID

#Bloom Filter - Junbeom In 2023
class BloomFilter:
    def __init__(self, items_count, fp_prob):
        #BITARRAY 사이즈
        self.size = self.get_size(items_count, fp_prob)
        #HASH FUNCTION 숫자 계산
        self.hash_count = self.get_hash_count(self.size, items_count)
        #BITARRAY 초기화
        self.bit_array = [0] * self.size

    #블룸필터 추가
    #Inserstion
    def add(self, item):
        #각각 HASH function 마다 반
        for i in range(self.hash_count):
            #각각 아이템 해쉬 계산
            digest = hashlib.md5((str(item) + str(i)).encode()).hexdigest()
            #계산되면 각각 비트어레이 1로 바꾸기
            self.bit_array[int(digest, 16) % self.size] = 1

    #찾기
    def is_member(self, item):
        #각각 Hash function 마다
        for i in range(self.hash_count):
            #Hash Item 계산 해서
            digest = hashlib.md5((str(item) + str(i)).encode()).hexdigest()
            #Bit가 0 일때 = Set에 없음
            if self.bit_array[int(digest, 16) % self.size] == 0:
                return False
        #Bit가 1 일때 = Set에 있음
        return True

    #사이즈 가져오기
    def get_size(cls, n, p):
        # 비트어레이 사이즈 가져오기 + FP rate랑
        #n = 블룸필터에 들어갈 갯수
        #p = FP
        #math.log = Less than 1 = Always negative
        #(math.log(2) = 제곱

        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    #해쉬 세기
    def get_hash_count(cls, m, n):
        #해쉬 Function 숫자 가져오기
        k = (m / n) * math.log(2)
        return int(k)

class BloomFilterCascade:
    def __init__(self, layers, items_count, fp_prob):
        self.layers = []
        # State (3) = Layer 몇개인지
        for i in range(layers):
            # 레이어마다 new Bloomfilter랑 FP rate 새로해서 올라감
            # False Positive  probability는 (i + 1)로 나누기
            # 따라오는 Follow-up layer들의 사이즈를 줄이기

            #1. Largre FP PROB Bloomfilter
            #2. Next bloomfilter has lesds less stages
            bloom_filter = BloomFilter(items_count, fp_prob / (i + 1))

            #새로 만들어진 Bloom Filter를 Layer에 올리기
            self.layers.append(bloom_filter)

    def generate_certificate(self):
        # 개인키 - Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 셀프 사인 만들기
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "PA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SCE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PSU"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # SPKI -> DER로 데리고 오기
        spki = certificate.public_key().public_bytes(Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # 시리얼넘버 추출
        serial_number = certificate.serial_number.to_bytes(20, 'big')

        return spki + serial_number

    #인증서 = Cascade 추가
    def insertion(self, certificate):
        for layer in self.layers:
            if not layer.is_member(certificate):
                layer.add(certificate)
                break

    #찾기
    def lookup(self, certificate):
        for layer in self.layers:
            if not layer.is_member(certificate):
                return False
        return True

    def generate_key(self, issuer_spki_der, serial_number_der):
        # Concatenate DER-encoded SPKI and serial number
        concatenated_data = issuer_spki_der + serial_number_der
        # Generate SHA256 digest of the concatenated data
        return hashlib.sha256(concatenated_data).hexdigest()




def evaluate_performance(cascade, num_certificates):
    certificates = []
    #Certificate Creation
    print(f"{num_certificates} certificates are creating now.")
    startTime = time.time()
    for i in range(0,num_certificates):
        certificates.append(cascade.generate_certificate())
    duration = time.time() - startTime
    print(f"Took : {duration}")

    #INSERTION
    print("Insertion")
    startTime = time.time()
    for i in certificates:
        cascade.insertion(i)
    insertion_time = time.time() - startTime
    print(f"Took : {insertion_time}")

    # LOOKUP
    print("Lookup")
    start_time = time.time()
    for i in certificates:
        cascade.lookup(i)
    lookup_time = time.time() - start_time
    print(f"Took : {lookup_time}")

    print(f"\nOn {num_certificates} certificates")
    print(f"Insertion throughput: {1000 / insertion_time} inserts/sec")
    print(f"Lookup throughput: {1000 / lookup_time} lookups/sec\n")

    return num_certificates,insertion_time,lookup_time

print("1. CASCADE CRATION")
cascade = BloomFilterCascade(layers=3, items_count=20, fp_prob=0.01)
print("   CASCADE CREATED")

print("2. evaluation")
result = []
result.append(evaluate_performance(cascade, 100))
result.append(evaluate_performance(cascade, 500))
result.append(evaluate_performance(cascade, 1000))
result.append(evaluate_performance(cascade, 5000))
result.append(evaluate_performance(cascade, 10000))

print(result)