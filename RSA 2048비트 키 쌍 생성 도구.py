#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# RSA 2048비트 키 쌍 생성 도구


import base64
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    USE_CRYPTOGRAPHY = True
except ImportError:
    USE_CRYPTOGRAPHY = False
    try:
        from Crypto.PublicKey import RSA
        USE_PYCRYPTODOME = True
    except ImportError:
        print("❌ 필요한 라이브러리가 설치되지 않았습니다.")
        print("\n다음 중 하나를 설치하세요:")
        print("1) pip install cryptography")
        print("2) pip install pycryptodome")
        print("\n현재 사용 중인 Python으로 설치:")
        import sys
        print(f"   {sys.executable} -m pip install cryptography")
        exit(1)


def generate_rsa_keys():
    # RSA 2048비트 키 쌍 생성
    print("=" * 70)
    print("🔐 RSA 2048-bit 키 쌍 생성 도구")
    print("=" * 70)
    print()
    print("🔑 키 생성 중...")
    
    if USE_CRYPTOGRAPHY:
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        
        private_numbers = private_key.private_numbers()
        public_numbers = public_key.public_numbers()
        
        key_data = {
            'n': public_numbers.n,
            'e': public_numbers.e,
            'd': private_numbers.d,
            'p': private_numbers.p,
            'q': private_numbers.q,
            'dp': private_numbers.dmp1,
            'dq': private_numbers.dmq1,
            'inv_q': private_numbers.iqmp
        }
    else:
        
        key = RSA.generate(2048)
        key_data = {
            'n': key.n,
            'e': key.e,
            'd': key.d,
            'p': key.p,
            'q': key.q,
            'dp': key.d % (key.p - 1),
            'dq': key.d % (key.q - 1),
            'inv_q': pow(key.q, -1, key.p)
        }
    
    # 공개키 XML 형식 생성
    public_key_xml = create_public_key_xml_from_numbers(key_data['n'], key_data['e'])
    
    # 개인키 XML 형식 생성  
    private_key_xml = create_private_key_xml_from_numbers(key_data)
    
    print("✅ 키 생성 완료!\n")
    
    # 화면에 출력
    print("=" * 70)
    print("📄 공개키 (Public Key) - XML 형식")
    print("=" * 70)
    print(public_key_xml)
    print()
    
    print("=" * 70)
    print("🔒 개인키 (Private Key) - XML 형식")
    print("=" * 70)
    print(private_key_xml)
    print()
    
    # 파일로 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    public_filename = f"PublicKey_{timestamp}.txt"
    private_filename = f"PrivateKey_{timestamp}.txt"
    
    with open(public_filename, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("RSA 2048-bit 공개키 (Public Key)\n")
        f.write(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write("XML 형식:\n")
        f.write("-" * 70 + "\n")
        f.write(public_key_xml)
        f.write("\n\n")
        f.write("=" * 70 + "\n")
        f.write("⚠️ 이 키는 암호화에 사용됩니다.\n")
        f.write("=" * 70 + "\n")
    
    with open(private_filename, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("RSA 2048-bit 개인키 (Private Key)\n")
        f.write(f"생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write("⚠️ 경고: 이 키를 절대 공개하지 마세요!\n")
        f.write("이 키는 암호화된 데이터를 복호화하는 데 사용됩니다.\n\n")
        f.write("XML 형식:\n")
        f.write("-" * 70 + "\n")
        f.write(private_key_xml)
        f.write("\n\n")
        f.write("=" * 70 + "\n")
        f.write("🔒 이 파일을 안전하게 보관하세요!\n")
        f.write("=" * 70 + "\n")
    
    print("=" * 70)
    print("💾 파일 저장 완료!")
    print("=" * 70)
    print(f"📁 공개키: {public_filename}")
    print(f"📁 개인키: {private_filename}")
    print()
    print("⚠️  개인키는 절대 공유하지 마세요!")
    print("=" * 70)


def create_public_key_xml_from_numbers(n, e):
    # 공개키를 XML 형식으로 변환
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    
    modulus_b64 = base64.b64encode(n_bytes).decode('utf-8')
    exponent_b64 = base64.b64encode(e_bytes).decode('utf-8')
    
    xml = "<RSAKeyValue>"
    xml += f"<Modulus>{modulus_b64}</Modulus>"
    xml += f"<Exponent>{exponent_b64}</Exponent>"
    xml += "</RSAKeyValue>"
    
    return xml


def create_private_key_xml_from_numbers(key_data):
    #개인키를 C# 호환 XML 형식으로 변환
    n_bytes = key_data['n'].to_bytes((key_data['n'].bit_length() + 7) // 8, 'big')
    e_bytes = key_data['e'].to_bytes((key_data['e'].bit_length() + 7) // 8, 'big')
    d_bytes = key_data['d'].to_bytes((key_data['d'].bit_length() + 7) // 8, 'big')
    p_bytes = key_data['p'].to_bytes((key_data['p'].bit_length() + 7) // 8, 'big')
    q_bytes = key_data['q'].to_bytes((key_data['q'].bit_length() + 7) // 8, 'big')
    dp_bytes = key_data['dp'].to_bytes((key_data['dp'].bit_length() + 7) // 8, 'big')
    dq_bytes = key_data['dq'].to_bytes((key_data['dq'].bit_length() + 7) // 8, 'big')
    inv_q_bytes = key_data['inv_q'].to_bytes((key_data['inv_q'].bit_length() + 7) // 8, 'big')
    
    modulus_b64 = base64.b64encode(n_bytes).decode('utf-8')
    exponent_b64 = base64.b64encode(e_bytes).decode('utf-8')
    p_b64 = base64.b64encode(p_bytes).decode('utf-8')
    q_b64 = base64.b64encode(q_bytes).decode('utf-8')
    dp_b64 = base64.b64encode(dp_bytes).decode('utf-8')
    dq_b64 = base64.b64encode(dq_bytes).decode('utf-8')
    inv_q_b64 = base64.b64encode(inv_q_bytes).decode('utf-8')
    d_b64 = base64.b64encode(d_bytes).decode('utf-8')
    
    xml = "<RSAKeyValue>"
    xml += f"<Modulus>{modulus_b64}</Modulus>"
    xml += f"<Exponent>{exponent_b64}</Exponent>"
    xml += f"<P>{p_b64}</P>"
    xml += f"<Q>{q_b64}</Q>"
    xml += f"<DP>{dp_b64}</DP>"
    xml += f"<DQ>{dq_b64}</DQ>"
    xml += f"<InverseQ>{inv_q_b64}</InverseQ>"
    xml += f"<D>{d_b64}</D>"
    xml += "</RSAKeyValue>"
    
    return xml


if __name__ == "__main__":
    generate_rsa_keys()