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

void yct14_setup(const int* attrs, unsigned int num_attrs,
		void** pubParBuff, void** prvParBuff);

#ifdef __cplusplus
}
#endif

#endif /* KPABE_YCT14_CPP_KPABE_H_ */
