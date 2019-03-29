#include <string.h>
#include <math.h>
#if defined(CONTIKI_TARGET_ZOUL)
extern "C" { // C "headers" coming
#include <dev/cbc.h>
#include <dev/sha256.h>
}
#else
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#endif
#include <pbc.h>

#include "kpabe.hpp"

using namespace std;

static void printf_byte_array(char* array, size_t array_len){
	size_t i;

	for( i = 0; i < array_len; i++){
	    printf("%02X", (uint8_t) array[i]);
	    fflush(stdout);
	}
}

// For the encrypt/decrypt methods.
static const size_t AES_BLOCK_SIZE = 16;
static const size_t AES_KEY_SIZE = 32;

pairing_s pairing;
uint8_t isInit = 0;

pairing_ptr getPairing() {
   if(!isInit) {
	   pairing_init_set_str(&pairing, TYPE_A_PARAMS);
	   isInit = 1;
   }

   return &pairing;
}

void hashElement(element_t* e, uint8_t* hashBuf) {
//	char tmp[512];
//	element_snprintf(tmp, 512, "[hashElement] e=%B\n", *e);
//	printf(tmp);

	int elementSize = element_length_in_bytes(*e);
	uint8_t* elementBytes = (uint8_t*) malloc(elementSize + 1);
	element_to_bytes(elementBytes, *e);

#if defined(CONTIKI_TARGET_ZOUL)
   uint8_t ret;
   crypto_init();

   sha256_state_t state;
   if( (ret = sha256_init(&state)) != CRYPTO_SUCCESS ){
   	printf("ERROR: initializing sha256 structure (error: %u)", ret);
   	exit(1);
   }

   if( (ret = sha256_process(&state, elementBytes, elementSize+1)) != CRYPTO_SUCCESS){
   	printf("ERROR: performing sha256 operation (error: %u)", ret);
   	exit(1);
   }

   if( (ret = sha256_done(&state, hashBuf)) != CRYPTO_SUCCESS){
   	printf("ERROR: getting result of sha256 operation (error: %u)", ret);
   	exit(1);
   }

   crypto_disable();

   printf("[hashElement] hashBuf=");
   printf_byte_array((char*) hashBuf, AES_KEY_SIZE);
   printf("\n");
#else
   const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
   mbedtls_md(mdInfo, elementBytes, elementSize, hashBuf);
#endif
   
   free(elementBytes);
}

/**
 * Common interface to for symmetric encryption and decryption.
 *
 * Uses AES-256-CBC and zero-filled IV.
 */
#if !defined(CONTIKI_TARGET_ZOUL)
void mbedtlsSymCrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t* output, size_t* olen, mbedtls_operation_t mode) {
   const mbedtls_cipher_info_t* cipherInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
   mbedtls_cipher_context_t ctx;
   mbedtls_cipher_setup(&ctx, cipherInfo);
   mbedtls_cipher_setkey(&ctx, key, cipherInfo->key_bitlen, mode);
   uint8_t iv[AES_BLOCK_SIZE];
   memset(iv, 0, AES_BLOCK_SIZE);
   mbedtls_cipher_crypt(&ctx, iv, cipherInfo->iv_size, input, ilen, output, olen);
}
#endif

void symEncrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t* output, size_t* olen) {
#if defined(CONTIKI_TARGET_ZOUL)
	/* stuff in real length (big endian) before padding */
	size_t ifinal_len = 4 + ilen;
	ifinal_len += (32 - ((int) ifinal_len % 32));
	char* ifinal = (char*) calloc(ifinal_len, sizeof(char));

	ifinal[0] = (ilen & 0xff000000)>>24;
	ifinal[1] = (ilen & 0xff0000)>>16;
	ifinal[2] = (ilen & 0xff00)>>8;
	ifinal[3] = (ilen & 0xff)>>0;
	memcpy(ifinal + 4, input, ilen);

	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0, AES_BLOCK_SIZE);

	crypto_init();

	uint8_t ret;
	if( (ret = aes_load_keys((char*) key, AES_KEY_STORE_SIZE_KEY_SIZE_256, 1, 0)) != CRYPTO_SUCCESS){
		printf("ERROR: loading keys (error: %d)\n", ret);
		exit(1);
	}

	if( (ret = cbc_crypt_start(1, 0, iv, ifinal, (char*) output, ifinal_len, NULL)) != CRYPTO_SUCCESS){
		printf("ERROR: starting cbc operation (error: %d)\n", ret);
		exit(1);
	}

	do {
		ret = cbc_crypt_check_status();
	} while(ret == -1 || ret == 255);
	/* otherwise continues with error 255 */

	if( ret != CRYPTO_SUCCESS ){
		printf("ERROR: performing cbc operation (error: %d)\n", ret);
		exit(1);
	}

	crypto_disable();

	free(ifinal);
	*olen = ifinal_len;

#else
   mbedtlsSymCrypt(input, ilen, key, output, olen, MBEDTLS_ENCRYPT);
#endif
}

void symDecrypt(const uint8_t* input, size_t ilen, uint8_t* key, uint8_t** output, size_t* olen) {
#if defined(CONTIKI_TARGET_ZOUL)
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0, AES_BLOCK_SIZE);

	char* ofinal = (char*) malloc(ilen);

	crypto_init();

	uint8_t ret;
	if( (ret = aes_load_keys((char*) key, AES_KEY_STORE_SIZE_KEY_SIZE_256, 1, 0)) != CRYPTO_SUCCESS){
		printf("ERROR: loading keys (error: %d)\n", ret);
		exit(1);
	}

	if( (ret = cbc_crypt_start(0, 0, iv, (char*) input, ofinal, ilen, NULL)) != CRYPTO_SUCCESS){
		printf("ERROR: starting cbc operation (error: %d)\n", ret);
		exit(1);
	}

	do {
		ret = cbc_crypt_check_status();
	} while(ret == -1 || ret == 255);
	/* otherwise continues with error 255 */

	if( ret != CRYPTO_SUCCESS ){
		printf("ERROR: performing cbc operation (error: %d)\n", ret);
		exit(1);
	}

	crypto_disable();

	/* get real length */
	*olen = 0;
	*olen = *olen
	    | ((ofinal[0])<<24) | ((ofinal[1])<<16)
	    | ((ofinal[2])<<8)  | ((ofinal[3])<<0);

	/* truncate any garbage from the padding */
	*output = (uint8_t*) malloc(*olen);
	memcpy(*output, ofinal + 4, *olen);
	free(ofinal);

	crypto_disable();
#else
   mbedtlsSymCrypt(input, ilen, key, *output, olen, MBEDTLS_DECRYPT);
#endif
}

// Node

Node::Node(const Node& other) {
   attr = other.attr;
   type = other.type;
   children = other.children;
   children_len = other.children_len;
}

Node::Node(Node&& other):
   attr(other.attr),
   type(other.type),
   children(other.children),
   children_len(other.children_len){
}

Node::Node(int attr) {
   this->attr = attr;
   this->type = Type::AND;
   this->children = NULL;
   this->children_len = 0;
}

Node::Node(Type type, Node* children, size_t children_len) {
   this->children = children;
   this->type = type;
   this->children_len = children_len;
   this->attr = 0;
}

Node& Node::operator=(Node other) {
	//TODO: check if not self
	//assert(this != &other);
	attr = other.attr;
	type = other.type;
	children = other.children;
	children_len = other.children_len;
	return *this;
}

void Node::addChild(const Node& node) {
   Node* tmp = (Node*) malloc((this->children_len+1)*sizeof(Node));
   if(children_len > 0) {
	   memcpy(tmp, children, this->children_len*sizeof(Node));
   }
   tmp[this->children_len] = node;

   free(children);
   children = tmp;
   this->children_len++;
}

/* TODO: Consider rewriting in iterative way to avoid frequent malloc-free */
void Node::getLeafs(int** attrs, size_t* attrs_len) const {
	int* tmp = NULL;

	if(children_len == 0) {
	   // Handles non-leaf node with one child
	   tmp = (int*) malloc((*attrs_len+1)*sizeof(int));
	   if(*attrs_len > 0){
		   memcpy(tmp, *attrs, *attrs_len*sizeof(int));
	   }
	   tmp[*attrs_len] = attr;

	   free(*attrs);
	   *attrs = tmp;
	   (*attrs_len)++;
   } else {
	   unsigned int i;

	   for(i = 0; i < children_len; i++) {
		   if(children[i].children_len == 0) {
			   //attrs.push_back(child.attr);
			   tmp = (int*) malloc((*attrs_len+1)*sizeof(int));
			   if(*attrs_len > 0){
				   memcpy(tmp, *attrs, *attrs_len*sizeof(int));
			   }
			   tmp[*attrs_len] = children[i].attr;

			   free(*attrs);
			   *attrs = tmp;
			   (*attrs_len)++;
		   } else {
			   children[i].getLeafs(attrs, attrs_len);
		   }
	   }
   }
}

unsigned int Node::getThreshold() const {
   return type == Type::OR ? 1 : static_cast<unsigned int>(children_len);
}

unsigned int Node::getPolyDegree() const {
   return getThreshold() - 1;
}

size_t Node::splitShares(element_t** shares, element_t rootSecret) {
	unsigned int x;

	// Generate the coefficients for the polynomial.
	unsigned int threshold = getThreshold();
	element_t* coeff = (element_t*) malloc(threshold*sizeof(element_t));
   
	element_init_same_as(coeff[0], rootSecret);
	element_set(coeff[0], rootSecret);
   
	// Generate random coefficients, except for q(0), which is set to the rootSecret.
	for(int i = 1; i <= getPolyDegree(); ++i) {
		element_init_same_as(coeff[i], rootSecret);
		element_random(coeff[i]);
	}

	// Calculate the shares for each child.
	*shares = (element_t*) malloc(children_len*sizeof(element_t));
   
	element_t temp;
	element_init_Zr(temp, getPairing());

   // The scheme decription defines an ordering on the children in a node (index(x)).
   // Here, we implicitly use a left to right order.
   for(x = 1; x <= children_len; ++x) {
      element_t* share = &((*shares)[x - 1]);
      element_init_same_as(*share, rootSecret);
      element_set0(*share);
      // share = coeff[0] + coeff[1] * x + ... + coeff[threshold - 1] * x ^ (threshold - 1)
      for(int power = 0; power < threshold; ++power) {
         element_set_si(temp, pow(x, power)); //TODO: handle pow
         element_mul(temp, temp, coeff[power]);
         element_add(*share, *share, temp);
      }
   }
   
   element_clear(temp);
   for(x = 0; x < threshold; x++) {
      element_clear(coeff[x]);
   }
   free(coeff);
   
   return children_len;
}//splitShares

/* TODO: Consider rewriting in iterative way to avoid frequent malloc-free */
void Node::getSecretShares(element_t** shares, size_t* shares_len, element_t rootSecret) {
   if(children_len == 0) {
	   element_t* tmp = (element_t*) malloc((*shares_len+1)*sizeof(element_t));
	   if(*shares_len > 0){
		   memcpy(tmp, *shares, (*shares_len)*sizeof(element_t));
	   }
	   memcpy(tmp + *shares_len, rootSecret, sizeof(element_t));

	   free(*shares);
	   *shares = tmp;
	   (*shares_len)++;
   } else {
	   unsigned int i;

	  element_t* childSplits = NULL;
	  size_t childSplitsLen = splitShares(&childSplits, rootSecret);
      for(i = 0; i < children_len; i++) {
    	  children[i].getSecretShares(shares, shares_len, childSplits[i]);
      }
      free(childSplits);
   }
}

size_t Node::recoverCoefficients(element_t** coeff) {
	unsigned int threshold = getThreshold();
	*coeff = (element_t*) malloc(threshold*sizeof(element_t));

	element_t iVal, jVal, temp;
	element_init_Zr(iVal, getPairing());
	element_init_Zr(jVal, getPairing());
	element_init_Zr(temp, getPairing());
   
	for(int i = 1; i <= threshold; ++i) {
		element_set_si(iVal, i);
		element_t* result = &(*coeff)[i - 1];
		element_init_Zr(*result, getPairing());
		element_set1(*result);
		for(int j = 1; j <= threshold; ++j) {
			if(i == j) {
				continue;
			}
			// result *= (0 - j) / (i - j)
			element_set_si(jVal, -j);
			element_add(temp, iVal, jVal);
			element_div(temp, jVal, temp);
			element_mul(*result, *result, temp);
		}
	}

	element_clear(iVal);
	element_clear(jVal);
	element_clear(temp);
   
	return threshold;
}

/* TODO: Consider rewriting in iterative way to avoid frequent malloc-free */
void Node::satisfyingAttributes(int** ret1, element_t** ret2, size_t* ret_len, int* attributes, size_t attrs_len,
                        element_t* currentCoeff) {
	unsigned int i;

	if (children_len == 0) {
		for(i = 0; i < attrs_len; i++) {
			if(attributes[i] == attr){
				break;
			}
		}

		if(i < attrs_len){
			//sat.push_back({attr, currentCoeff});
			int* tmp1 = (int*) malloc((*ret_len+1)*sizeof(int));
			element_t* tmp2 = (element_t*) malloc((*ret_len+1)*sizeof(element_t));
			if(*ret_len > 0){
				memcpy(tmp1, *ret1, (*ret_len)*sizeof(int));
				memcpy(tmp2, *ret2, (*ret_len)*sizeof(element_t));
			}
			tmp1[*ret_len] = attr;
			memcpy(tmp2 + *ret_len, currentCoeff, sizeof(element_t));

			free(*ret1);
			free(*ret2);
			*ret1 = tmp1;
			*ret2 = tmp2;
			(*ret_len)++;
		}
	} else {
		element_t* coeff = NULL;
		size_t coeff_len = recoverCoefficients(&coeff);
      
		if(type == Type::AND) {
			int* totalChildSat1 = NULL;
			element_t* totalChildSat2 = NULL;
			size_t totalChildSatLen = 0;

			for(i = 0; i < children_len; ++i) {
				element_mul(coeff[i], coeff[i], *currentCoeff);
				children[i].satisfyingAttributes(ret1, ret2, ret_len, attributes, attrs_len, &coeff[i]);
			}
		} else {
			element_t* recCoeff0 = &coeff[0];
			element_mul(*recCoeff0, *recCoeff0, *currentCoeff);
			for (i = 0; i < children_len; ++i) {
				children[i].satisfyingAttributes(ret1, ret2, ret_len, attributes, attrs_len, recCoeff0);
			}
		}
	}
}

size_t Node::getChildren(Node** ret_children) const {
	*ret_children = children;
	return children_len;
}

// DecryptionKey

DecryptionKey::DecryptionKey(Node* policy): accessPolicy(policy) {
	Di1 = NULL;
	Di2 = NULL;
	Di_len = 0;
}

DecryptionKey::DecryptionKey(const DecryptionKey& other):
	Di1(other.Di1), Di2(other.Di2), Di_len(other.Di_len),
	accessPolicy(other.accessPolicy) { }

DecryptionKey& DecryptionKey::operator=(DecryptionKey other) {
	//TODO: check if not self
	//assert(this != &other);
	Di1 = other.Di1;
	Di2 = other.Di2;
	Di_len = other.Di_len;
	accessPolicy = other.accessPolicy;
	return *this;
}

// Algorithm Setup

void setup(const int* attributes, size_t attrs_len,
           PublicParams** publicParams,
           PrivateParams** privateParams) {
   *publicParams = (PublicParams*) malloc(sizeof(PublicParams));
   *privateParams = (PrivateParams*) malloc(sizeof(PrivateParams));
   
   element_init_Zr((*privateParams)->mk, getPairing());
   element_random((*privateParams)->mk);

   element_t g;
   element_init_G1(g, getPairing());
   element_random(g);
   
   // Generate a random public and private element for each attribute
   (*publicParams)->Pi1 = (int*) malloc(attrs_len*sizeof(int));
   (*publicParams)->Pi2 = (element_t*) malloc(attrs_len*sizeof(element_t));
   (*publicParams)->Pi_len = attrs_len;

   (*privateParams)->Si1 = (int*) malloc(attrs_len*sizeof(int));
   (*privateParams)->Si2 = (element_t*) malloc(attrs_len*sizeof(element_t));
   (*privateParams)->Si_len = attrs_len;

   unsigned int i,j;
   for(i = 0; i < attrs_len; i++) {
	   // private
	   (*privateParams)->Si1[i] = attributes[i];
	   element_init_Zr((*privateParams)->Si2[i], getPairing());
	   element_random((*privateParams)->Si2[i]);
      
	   // public
	   (*publicParams)->Pi1[i] = attributes[i];
	   element_init_G1((*publicParams)->Pi2[i], getPairing());
	   element_pow_zn((*publicParams)->Pi2[i], g, (*privateParams)->Si2[i]);
   }
   
   element_init_G1((*publicParams)->pk, getPairing());
   element_pow_zn((*publicParams)->pk, g, (*privateParams)->mk);
   element_clear(g);
}

/**
 * @brief An abstraction of createKey that allows different operation for hiding the
 *    secret shares.
 *
 * @param scramblingFunc A function that sets an element to the result of a function on
 *    a scambling key and a secret share. In the original paper the scrambling keys are
 *    the private keys and the function is division. The result of the scrambling is put
 *    in the first element, the shares in the second, the scramblng keys in the third.
 * @type scramblingFunc function<void (element_t, element_t, element_t)>
 */
DecryptionKey _keyGeneration(element_t rootSecret,
		int* scramblingKeys1,
		element_t* scramblingKeys2,
		size_t scramblingKeysLen,
		void scramblingFunc(element_t, element_t, element_t),
		Node* accessPolicy) {

   int* leafs = NULL;
   size_t leafs_len = 0;
   accessPolicy->getLeafs(&leafs, &leafs_len);
   element_t* shares = NULL;
   size_t shares_len = 0;
   accessPolicy->getSecretShares(&shares, &shares_len, rootSecret);
   
   DecryptionKey key(accessPolicy);
   key.Di1 = (int*) malloc(leafs_len*sizeof(int));
   key.Di2 = (element_t*) malloc(leafs_len*sizeof(element_t));
   key.Di_len = leafs_len;

   // The below is: Du[attr] = shares[attr] / attributeSecrets[attr]
   unsigned int i, j;
   for(i = 0; i < leafs_len; i++) {
	   element_t* scramblingKey;
	   for(j = 0; j < scramblingKeysLen; j++){
		   if(scramblingKeys1[j] == leafs[i]){
			   scramblingKey = &scramblingKeys2[j];
			   break;
		   }
	   }

	   key.Di1[i] = leafs[i];
	   element_init_Zr(key.Di2[i], getPairing());
	   scramblingFunc(key.Di2[i], shares[i], *scramblingKey);
   }
   
   for(i = 0; i < shares_len; i++) {
      element_clear(shares[i]);
   }
   free(shares);
   free(leafs);
   
   return key;
}


DecryptionKey keyGeneration(PrivateParams* privateParams, Node* accessPolicy) {
   return _keyGeneration(privateParams->mk, privateParams->Si1, privateParams->Si2,
		   privateParams->Si_len, element_div, accessPolicy);
}

void createSecret(Cw_t** Cw, PublicParams* params,
                 const int* attributes, size_t attrs_len,
                 element_t* Cs) {
   element_t k;
   element_init_Zr(k, getPairing());
   element_random(k);

   element_init_G1(*Cs, getPairing());
   element_pow_zn(*Cs, params->pk, k);
   
   *Cw = (Cw_t*) malloc(sizeof(Cw_t));
   (*Cw)->index = (int*) malloc(attrs_len*sizeof(int));
   (*Cw)->elem = (element_t*) malloc(attrs_len*sizeof(element_t));
   (*Cw)->len = attrs_len;

   unsigned int i, j;
   for(i = 0; i < attrs_len; i++) {
      (*Cw)->index[i] = attributes[i];
      element_init_G1((*Cw)->elem[i], getPairing());

      element_t* param;
      for(j = 0; j < params->Pi_len; j++){
    	  if(params->Pi1[j] == attributes[i]){
    		  param = &params->Pi2[j];
    		  break;
    	  }
      }
      element_pow_zn((*Cw)->elem[i], *param, k);
   }
   element_clear(k);
}

void recoverSecret(DecryptionKey* key,
                   Cw_t* Cw,
                   int* attributes, size_t attrs_len,
                   element_t* Cs) {
   // Get attributes that can satisfy the policy (and their coefficients).
   element_t rootCoeff;
   element_init_Zr(rootCoeff, getPairing());
   element_set1(rootCoeff);

   int* sat1 = NULL;
   element_t* sat2 = NULL;
   size_t sat_len = 0;

   key->accessPolicy->satisfyingAttributes(&sat1, &sat2, &sat_len, attributes, attrs_len, &rootCoeff);
   //element_clear(rootCoeff);

   if(sat_len == 0) {
	   printf("WARNING: policy not satisfied\n");
	   return;
   }
   
   element_t Zy;
   element_init_G1(*Cs, getPairing());
   element_init_G1(Zy, getPairing());
   bool pastFirst = false; // Is this the first "part" of the product
   
   // product = P(Ci ^ (Di * coeff(i)))
   // NOTE: attrCoeffPair is modified
   unsigned int i, j;
   for(i = 0; i < sat_len; i++) {
	   element_t* attrDi;
	   for(j = 0; j < key->Di_len; j++){
		   if(key->Di1[j] == sat1[i]){
			   attrDi = &key->Di2[j];
			   break;
		   }
	   }
      element_mul(sat2[i], *attrDi, sat2[i]);

      element_t* elem;
      for(j = 0; j < Cw->len; j++){
    	  if(Cw->index[j] == sat1[i]){
    		  elem = &Cw->elem[j];
    		  break;
    	  }
      }
      element_pow_zn(Zy, *elem, sat2[i]);
   
      if (pastFirst) {
         element_mul(*Cs, *Cs, Zy);
      } else {
         pastFirst = true;
         element_set(*Cs, Zy);
      }
   }
   
   free(sat1);
   for(i = 0; i < sat_len; i++){
      element_clear(sat2[i]);
   }
   free(sat2);
   element_clear(Zy);
}

size_t encrypt(uint8_t** ct,
		PublicParams* params, const int* attributes, size_t attrs_len,
		char* message, Cw_t** Cw) {
   element_t Cs;
   createSecret(Cw, params, attributes, attrs_len, &Cs);
   
   // Use the key to encrypt the data using a symmetric cipher.
   size_t messageLen = strlen(message) + 1; // account for terminating byte
   size_t cipherMaxLen = 4 + messageLen;
   cipherMaxLen += (32 - ((int) cipherMaxLen % 32));
   *ct = (uint8_t*) malloc(cipherMaxLen*sizeof(uint8_t));

   uint8_t key[AES_KEY_SIZE];
   hashElement(&Cs, key);
   element_clear(Cs);

   size_t clength = 0;
   symEncrypt((uint8_t*) message, messageLen, key, *ct, &clength);

   return clength;
}

char* decrypt(DecryptionKey* key,
                    Cw_t* Cw,
                    int* attributes, size_t attrs_len,
                    uint8_t* ciphertext, size_t ct_len) {
   element_t Cs;
   recoverSecret(key, Cw, attributes, attrs_len, &Cs);

   uint8_t symKey[AES_KEY_SIZE];
   hashElement(&Cs, symKey);
   element_clear(Cs);

   uint8_t* plaintext =
#if defined(CONTIKI_TARGET_ZOUL)
		   NULL;
#else
   	   	   (uint8_t*) malloc(ct_len);
#endif
   size_t plaintextLen = 0;
   symDecrypt(ciphertext, ct_len, symKey, &plaintext, &plaintextLen);
   
   return (char*) plaintext;
}
