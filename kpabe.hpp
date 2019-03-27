#ifndef kpabe_
#define kpabe_

#include <pbc.h>

//#pragma GCC visibility push(default)

/**
 * @brief KP-ABE implicit parameters.
 */
#define TYPE_A_PARAMS \
"type a\n" \
"q 25592495515765067051642300423336670621430538560550086238294375266242321140927190193065045904197241858828084036025639\n" \
"h 35022192055157566125252273151275491786431099978820680852024212634920\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

/**
 * @brief Returns a pairing object.
 *
 * We only ever need one.
 */
pairing_ptr getPairing();

/**
 * @brief Compute a hash from an element.
 */
void hashElement(element_t e, uint8_t* key);

class Node {
   
public:
   enum Type { OR, AND };
   
   int attr;
   
private:
   Type type;
   Node* children;
   size_t children_len;

public:
   Node(const Node& other);
   Node(Node&& other);
   Node(int attr);
   Node(Type type, Node* children = NULL, size_t children_len = 0);
   
   Node& operator=(Node other);
   
   void addChild(const Node& node);
   size_t getChildren(Node** ret_children) const;
   
   //TODO: Abstract traversal order
   /**
    * @brief Returns all leaf nodes under the given node.
    */
   void getLeafs(int** attrs, size_t* attrs_len) const;
   unsigned int getThreshold() const;
   unsigned int getPolyDegree() const;
   
   /**
    * @brief Split the given secret share to the children of the given node.
    *
    * This sets p(0) = rootSecret and generates a random getPolyDegree polynomial.
    * The index of the shares follow the index of the children of the node + 1 (index 0 is
    * the root secret).
    */
   size_t splitShares(element_t** shares, element_t rootSecret);

   //TODO: Abstract tree traversal
   /**
    * @brief Performs Shamir's secret-sharing scheme in a top-down manner.
    *
    * The secret shares for the access tree are returned as a vector, where the positions
    * correspond to the left-to-right tree traversal.
    */
   void getSecretShares(element_t** shares, size_t* shares_len, element_t rootSecret);
   
   /**
    * @brief Computes the Lagrange coefficients.
    *
    * Assumes an interpolated value of 0 and that the children of the node have index()
    * values in the range 1..#numChildren.
    */
   size_t recoverCoefficients(element_s** ret);
   
   /**
    * @brief Computes the Lagrange coefficients for a satisfying subset of attributes.
    *
    * @return A vector of attribute-coefficient pairs.
    */
   void satisfyingAttributes(int** ret1, element_s** ret2, size_t* ret_len, int* attributes, size_t attrs_len,
                           element_s* currentCoeff);
};

class DecryptionKey {

public:
   Node accessPolicy;
   int* Di1;
   element_t* Di2;
   size_t Di_len;

   DecryptionKey(const DecryptionKey& other);
   DecryptionKey(const Node& policy);

   DecryptionKey& operator=(DecryptionKey other);
};

typedef struct {
   element_t pk;
   int* Pi1;
   element_t* Pi2;
   size_t Pi_len;
} PublicParams;

typedef struct {
   element_t mk;
   int* Si1;
   element_t* Si2;
   size_t Si_len;
} PrivateParams;

typedef struct {
	int* index;
	element_s* elem;
	size_t len;
} Cw_t;

/**
 * @brief Generates the public and private parameters of the scheme.
 */
void setup(const int* attributes, size_t attrs_len,
           PublicParams** publicParams,
           PrivateParams** privateParams);

/**
 * @brief Creates a decryption key.
 *
 * This is the KeyGeneration algorithm.
 */
DecryptionKey keyGeneration(PrivateParams* privateParams, Node* accessPolicy);

/**
 * @brief Creates a KP-ABE secret.
 *
 * This is the Encryption algorithm, but without deriving a key and encryption.
 * Ciphertext C will hold the decryption parameters, the secret is Cs.
 */
Cw_t createSecret(PublicParams& params,
                 const int* attributes, size_t attrs_len,
                 element_s& Cs);

/**
 * @brief Recovers a KP-ABE secret using the decryption key and decryption parameters.
 */
void recoverSecret(DecryptionKey& key,
                   Cw_t& Cw,
                   int* attributes, size_t attrs_len,
                   element_s& Cs);

/**
 * @brief Encrypts a message under a given attribute set.
 *
 * This is the actual Encryption algorithm, but without a HMAC.
 */
size_t encrypt(uint8_t** ct,
		PublicParams& params, const int* attributes, size_t attrs_len,
		char* message, Cw_t& Cw);

/**
 * @brief Decrypts an attribute-encrypted message.
 *
 * This is the actual Decryptoon algorithm, but without a HMAC.
 */
char* decrypt(DecryptionKey& key,
                    Cw_t& Cw,
                    int* attributes, size_t attrs_len,
                    uint8_t* ciphertext, size_t ct_len);

//#pragma GCC visibility pop
#endif
