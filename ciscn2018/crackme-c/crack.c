#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
unsigned char result[] = {165, 193, 20, 213, 243, 228, 45, 177, 127, 224, 123, 173, 218, 196, 65, 180};

void main(){
	int fd, i;

	fd = open("bin",O_RDONLY);
	if (fd < 0){
		printf("err\n");
		return;
	}
	unsigned int *array;
	array = (unsigned int*)malloc(37888 * sizeof(unsigned int));
	if(array == 0){
		printf("malloc err\n");
		return;
	}

	for(i = 0; i< 37888; i++){
		read(fd,((void *)array+i*4),4);
	}

	int tmp;
	tmp = result[13];
	result[13] = result[9];
	result[9] = result[5];
	result[5] = result[1];
	result[1] = tmp;
	tmp = result[2];
	result[2] = result[10];
	result[10] = tmp;
	tmp = result[6];
	result[6] = result[14];
	result[14] = tmp;
	tmp = result[7];
	result[7] = result[11];result[11] = result[15];
	result[15] = result[3];
	result[3] = tmp;
	
	int x,y,z,k, j;
	int flag = 0;
	i = 8;
	printf("start\n");
	for(i = 8;i>=0;i--){
		printf("i: %d\n", i);
		for(j = 0; j < 4; j++){
			flag = 0;
			printf("j: %d\n", j);
			for(x = 0;x <=0xff; x++){
				//printf("x: %x\n", x);
				for(y = 0;y <=0xff; y++){
					for(z=0;z<=0xff;z++){
						for(k=0;k<=0xff;k++){
							if((array[((4*j+3+16*i)<<8) + x] ^ array[((4*j+2+16*i)<<8) + y] ^ array[((4*j+1+16*i)<<8) + z]^array[((4*j+0+16*i)<<8) + k]) == ((unsigned int *)result)[j]){
								printf("%x\n",k | (z << 8) | (y << 16) | (x << 24));
								printf("x,y,z,k: %x %x %x %x\n", x,y,z,k);
								result[j*4+0] = (unsigned char)k;
								result[j*4+1] = (unsigned char)z;
								result[j*4+2] = (unsigned char)y;
								result[j*4+3] = (unsigned char)x;
								flag = 1;
								break;
							}
						}
						if(flag)
							break;
					}
					if(flag)
						break;
				}
				if(flag)
					break;
			}
		}
		int tmp;
		tmp = result[13];
		result[13] = result[9];
		result[9] = result[5];result[5] = result[1];
		result[1] = tmp;
		tmp = result[2];
		result[2] = result[10];
		result[10] = tmp;
		tmp = result[6];
		result[6] = result[14];
		result[14] = tmp;
		tmp = result[7];
		result[7] = result[11];
		result[11] = result[15];
		result[15] = result[3];
		result[3] = tmp;
	}
}