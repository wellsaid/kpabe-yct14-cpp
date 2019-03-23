/*
 * kpabe_c_wrapper.c
 *
 *  Created on: Mar 19, 2019
 *      Author: wellsaid
 */

#include "kpabe.hpp"
#include "kpabe.h"

extern "C" {

void yct14_setup(const int* attrs, unsigned int num_attrs,
		void** pubParBuff, void** prvParBuff) {
	setup(attrs, num_attrs, (PublicParams**) pubParBuff, (PrivateParams**) prvParBuff);
}

}
