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
void yct14_setup(int* attributes, unsigned int num_attr,
		void* publicParams, void* privateParams);

#endif /* KPABE_YCT14_CPP_KPABE_H_ */
