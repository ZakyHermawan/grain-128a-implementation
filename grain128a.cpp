#include <iostream>
#include <bitset>
#include <vector>
#include <string>

using bits128 = std::bitset<128>;
using bits96 = std::bitset<96>;
using bits32 = std::bitset<32>;
using bits8 = std::bitset<8>;
using vBits8 = std::vector<bits8>;
using vBool = std::vector<bool>;
using strMsg = std::string;

using std::cin;
using std::cout;
using std::endl;

class GrainCipher {
private:
	bits128 m_lfsr;
	bits128 m_nfsr;
	bits32 m_acc;
	bits32 m_sr;
	bool m_authMode;
	int m_A[7]{ 2, 15, 36, 45, 64, 73, 89 };
	
public:
	GrainCipher(bits128& key, bits96& IV);
	void initLFSR(bits96& IV);
	void initNFSR(bits128& key);
	void initStream();
	bool nextLFSR();
	bool nextNFSR();
	bool filter();
	bool nextStream();
	void getKeyStream(vBool& ks, vBits8& vMsg);
	bits32& authTag();
};

GrainCipher::GrainCipher(bits128& key, bits96& IV) {
	initLFSR(IV);
	initNFSR(key);
	initStream();
}

void GrainCipher::initLFSR(bits96& IV) {
	for (int i = 0; i < 96; ++i) {
		m_lfsr[i] = IV[i];
	}
	for (int i = 96; i < 127; ++i) {
		m_lfsr[i] = 1;
	}
	m_lfsr[127] = 0;
	m_authMode = m_lfsr[0];
}

void GrainCipher::initNFSR(bits128& key) {
	m_nfsr = key;
}

bool GrainCipher::nextNFSR() {
	return m_lfsr[0] ^ m_nfsr[0] ^ m_nfsr[26] ^ m_nfsr[56] ^ m_nfsr[91] ^ m_nfsr[96] ^ (m_nfsr[3] & m_nfsr[67])
		^ (m_nfsr[11] & m_nfsr[13]) ^ (m_nfsr[17] & m_nfsr[18]) ^ (m_nfsr[27] & m_nfsr[59])
		^ (m_nfsr[40] & m_nfsr[48]) ^ (m_nfsr[61] & m_nfsr[65]) ^ (m_nfsr[68] & m_nfsr[84])
		^ (m_nfsr[88] & m_nfsr[92] & m_nfsr[93] & m_nfsr[95]) ^ (m_nfsr[22] & m_nfsr[24] & m_nfsr[25])
		^ (m_nfsr[70] & m_nfsr[78] & m_nfsr[82]);
}

// use f(x) = 1 + x^32 + x^47 + x^58 + x^90 + x^121 + x^128
bool GrainCipher::nextLFSR() {
	return m_lfsr[0] ^ m_lfsr[7] ^ m_lfsr[38] ^ m_lfsr[70] ^ m_lfsr[81] ^ m_lfsr[96];
}

bool GrainCipher::filter() {
	bool x0 = m_nfsr[12];
	bool x1 = m_lfsr[8];
	bool x2 = m_lfsr[13];
	bool x3 = m_lfsr[20];
	bool x4 = m_nfsr[95];
	bool x5 = m_lfsr[42];
	bool x6 = m_lfsr[60];
	bool x7 = m_lfsr[79];
	bool x8 = m_lfsr[94];

	return (x0 & x1) ^ (x2 & x3) ^ (x4 & x5) ^ (x6 & x7) ^ (x0 & x4 & x8);
}


void GrainCipher::initStream() {
	if (m_authMode == 0) {
		return;
	}

	// use the first 32 bits of the stream to initialize accumulator
	for (size_t i = 0; i < 32; ++i) {
		m_acc[i] = nextStream();
	}

	// use the second 32 bits of the stream to initialize shift register
	for (size_t i = 0; i < 32; ++i) {
		m_sr[i] = nextStream();
	}
}

void GrainCipher::getKeyStream(vBool& ks, vBits8& vMsg) {
	size_t msg_len = vMsg.size();
	
	// if auth mode is disabled, z[i] = y[i]
	// else z[i] = y[2w+2i], we use w = 32 (32 bit tag, since our accumulator is 32 bit)
	if (m_authMode == 0) {
		for (size_t i = 0; i < msg_len * 8; ++i) {
			ks.push_back(nextStream());
		}
		return;
	}

	size_t msg_index = 0, y_index = 0;
	while (msg_index < msg_len * 8) {
		bool y = nextStream();

		if (y_index & 1) {
			if (vMsg[msg_index / 8][msg_index % 8]) {
				for (size_t i = 0; i < 32; ++i) {
					m_acc[i] = m_acc[i] ^ m_sr[i];
				}
			}
			m_sr >>= 1;
			m_sr[31] = y;
			++msg_index;
		}
		else {
			ks.push_back(y);
		}
		++y_index;
	}
}

bool GrainCipher::nextStream() {

	bool lfsr_fb = nextLFSR();
	bool nfsr_fb = nextNFSR();
	bool h = filter();

	bool y = 0;
	for (int i = 0; i < 7; ++i) {
		y ^= m_nfsr[m_A[i]];
	}

	y ^= m_lfsr[93] ^ h;

	m_lfsr >>= 1;
	m_nfsr >>= 1;

	m_lfsr[127] = lfsr_fb ^ y;
	m_nfsr[127] = nfsr_fb ^ y;

	return y;
}

bits32& GrainCipher::authTag() {
	return m_acc;
}

vBits8 strToBin(strMsg& s) {
	size_t str_len = s.length();
	vBits8 v;
	for (size_t i = 0; i < str_len; ++i) {
		bits8 tmp_bit(s[i]);
		v.push_back(tmp_bit);
	}

	return v;
}



// enc = keystream ^ msg
// dec = keystream ^ enc

int main() {
	bits128 key;
	bits96 IV;
	vBool ks; // keystream
	size_t key_len;
	vBits8 enc;
	
	strMsg msg;

	// insert Key and IV in bits stream, ex: 1101010010111010....
	cout << "128 bits Key: ";
	cin >> key;
	cout << "128 bits IV: ";
	cin >> IV; 
	// if IV[0] (first bit of IV) = 1, authentication enabled. Otherwise (IV[0] = 0), authentication disabled
	// note: if IV = 11010, IV[0] = 0
	cin.ignore();

	
	cout << "Message: ";
	std::getline(cin, msg);
	
	vBits8 vMsg = strToBin(msg);

	// pad message with 1 
	vMsg.push_back(bits8("00000001"));

	size_t len_msg = vMsg.size();
	key_len = len_msg * 8;

	// Encryption process
	GrainCipher c(key, IV);
	c.getKeyStream(ks, vMsg);
	
	for (size_t i = 0; i < len_msg; ++i) {
		bits8 tmp;
		for (size_t j = i * 8; j < (i+1) * 8; ++j) {
			tmp[j - (i * 8)] = ks[j];
		}
		enc.push_back(tmp);
	}

	for (size_t i = 0; i < len_msg; ++i) {
		enc[i] = (vMsg[i] ^ enc[i]);
	}

	// enc[0][0].flip(); you can try to flip the bits to see if the authentication works
	// Decryption process
	GrainCipher d(key, IV);
	vBool dks; // decryption keystream
	vBits8 dec;
	d.getKeyStream(dks, enc);
	
	for (size_t i = 0; i < enc.size(); ++i) {
		bits8 tmp;
		for (size_t j = 0; j < 8; ++j) {
			tmp[j] = dks[j + i * 8];
		}
		dec.push_back(tmp);
	}

	for (size_t i = 0; i < dec.size(); ++i) {
		dec[i] = (dec[i] ^ enc[i]);
	}
	
	cout << "Decrypted message: ";
	strMsg s;
	for (size_t i = 0; i < dec.size()-1; ++i) {
		int nt = dec[i].to_ulong();
		s += (char)nt;
	}
	cout << s << endl << endl;

	cout << "Plaintext bits: ";
	for (size_t i = 0; i < vMsg.size(); ++i) {
		cout << vMsg[i] << " ";
	}
	cout << endl;

	cout << "Encrypted bits: ";
	for (size_t i = 0; i < len_msg; ++i) {
		cout << enc[i] << ' ';
	}
	cout << endl;
	cout << "Decrypted bits: ";
	for (size_t i = 0; i < dec.size(); ++i) {
		cout << dec[i] << " ";
	}
	cout << endl << endl;
	
	// tag verification
	GrainCipher plain(key, IV);
	vBool pks; // decryption keystream
	vBits8 pText{dec};
	plain.getKeyStream(pks, pText);
	
	cout << "Message tag: ";
	for (int i = 0; i < 32; ++i) {
		cout << c.authTag()[i];
	}
	cout << endl;

	cout << "Decrypt tag: ";
	for (int i = 0; i < 32; ++i) {
		cout << plain.authTag()[i];
	}
	cout << endl;

	for (int i = 0; i < 32; ++i) {
		if (plain.authTag()[i] != c.authTag()[i]) {
			cout << "Tag doesn't match!" << endl;
			return 1;
		}
	}

	cout << "Message authenticated" << endl;
	return 0;
}
