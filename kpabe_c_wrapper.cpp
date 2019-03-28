/*
 * kpabe_c_wrapper.c
 *
 *  Created on: Mar 19, 2019
 *      Author: wellsaid
 */

#include "kpabe.hpp"
#include "kpabe.h"

extern "C" {

void* build_yao_policies(int* attr_univ, size_t num_attr, uint8_t policy){
	Node* root = NULL;

	if(num_attr == 1){
		root = (Node*) malloc(sizeof(Node));
		*root = Node(attr_univ[0]);
		return root;
	}

	unsigned int i;
	Node* children = NULL, *tmp = NULL;
	size_t children_len = 0;
	switch(policy) {
		case YCT14_FLAT_POLICY:
			children_len = num_attr;
			children = (Node*) malloc(children_len*sizeof(Node));
			for(i = 0; i < num_attr; i++){
				children[i] = Node(attr_univ[i]);
			}
			break;
		case YCT14_3LEVEL_POLICY:
			children_len = num_attr/2 + (num_attr%2);
			children = (Node*) malloc(children_len*sizeof(Node));
			for(i = 0; i+2 <= num_attr; i+=2){
				tmp = (Node*) malloc(2*sizeof(Node));
				tmp[0] = Node(attr_univ[i]);
				tmp[1] = Node(attr_univ[i+1]);
				children[i/2] = Node(Node::Type::AND, tmp, 2);
			}
			if(num_attr%2){
				children[i/2] = Node(attr_univ[i]);
			}
			break;
		default:
			free(children);
			return NULL;
	}

	root = (Node*) malloc(sizeof(Node));
	*root = Node(Node::Type::AND, children, children_len);

	return root;
}

void yct14_setup(const int* attrs, unsigned int num_attrs,
		void** pubParBuff, void** prvParBuff) {
	setup(attrs, num_attrs, (PublicParams**) pubParBuff, (PrivateParams**) prvParBuff);
}


void* yct14_keygen(void* prvParBuff,
                            void* accessPolicyBuff) {
	PrivateParams* priv = (PrivateParams*) prvParBuff;
	Node* accPol = (Node*) accessPolicyBuff;

	DecryptionKey* key_dyn = (DecryptionKey*) malloc(sizeof(DecryptionKey));
	*key_dyn = keyGeneration(priv, accPol);

	return key_dyn;
}

size_t yct14_encrypt(uint8_t** ct, void* pubParBuff, const int* attributes, size_t attrs_len, char* message, void** CwBuff) {
	PublicParams* params = (PublicParams*) pubParBuff;
	Cw_t** Cw = (Cw_t**) CwBuff;

	return encrypt(ct, params, attributes, attrs_len, message, Cw);
}

char* yct14_decrypt(void* keyBuff,
                    void* CwBuff,
                    int* attributes, size_t attrs_len,
                    uint8_t* ciphertext, size_t ct_len){
	DecryptionKey* key = (DecryptionKey*) keyBuff;
	Cw_t* Cw = (Cw_t*) CwBuff;

	return decrypt(key, Cw, attributes, attrs_len, ciphertext, ct_len);
}

// memory freeing
void yct14_priv_free(void* prvParBuff) {
	PrivateParams* priv = (PrivateParams*) prvParBuff;

	//element_clear(priv->mk); /* TODO: Causes invalid access and crash later on */
	free(priv->Si1);
	for(unsigned int i = 0; i < priv->Si_len; i++){
		element_clear(priv->Si2[i]);
	}
	free(priv->Si2);
	free(prvParBuff);
}

void yct14_pub_free(void* pubParBuff) {
	PublicParams* pub = (PublicParams*) pubParBuff;

	element_clear(pub->pk);
	free(pub->Pi1);
	for(unsigned int i = 0; i < pub->Pi_len; i++){
			element_clear(pub->Pi2[i]);
	}
	free(pub->Pi2);
}

}
