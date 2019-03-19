/*
 * kpabe_c_wrapper.c
 *
 *  Created on: Mar 19, 2019
 *      Author: wellsaid
 */

#include "kpabe.hpp"
#include "kpabe.h"

extern "C" void yct14_setup(const int* attrs_c, unsigned int num_attrs,
		void* pubParBuff, void* prvParBuff) {

	std::vector<int> attrs_cpp;
	for(unsigned int i = 0; i < num_attrs; i++){
		attrs_cpp.push_back(attrs_c[i]);
	}

	setup(attrs_cpp, (PublicParams&) pubParBuff, (PrivateParams&) prvParBuff);
}
