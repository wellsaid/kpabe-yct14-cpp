/*
 * kpabe.h
 *
 *  Created on: Mar 19, 2019
 *      Author: wellsaid
 */

#ifndef KPABE_YCT14_CPP_KPABE_H_
#define KPABE_YCT14_CPP_KPABE_H_

/**
 * @brief Generates the public and private parameters of the scheme.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* list of possible policies */
/**
 * @brief Worst case policy
 *
 * A policy with all attributes in an AND
 */
#define YCT14_FLAT_POLICY 1
/**
 * @brief "Flat" policy
 *
 * A policy with all attributes like this: (a AND b) AND (c AND d) ...
 */
#define YCT14_3LEVEL_POLICY 2

void* build_yao_policies(int* attr_univ, size_t num_attr, uint8_t policy);

void yct14_setup(const int* attrs, unsigned int num_attrs,
		void** pubParBuff, void** prvParBuff);

void yct14_priv_free(void* prvParBuff);

void* yct14_keygen(void* prvParBuff, void* accessPolicyBuff);

size_t yct14_encrypt(uint8_t** ct, void* pubParBuff, const int* attributes, size_t attrs_len, char* message, void** CwBuff);

#ifdef __cplusplus
}
#endif

#endif /* KPABE_YCT14_CPP_KPABE_H_ */
