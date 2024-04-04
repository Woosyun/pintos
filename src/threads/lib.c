/* --- project 1.3 start --- */
#include <stdint.h>
#define F (1<<14)

int fp_to_int (int);
int fp_to_int_round (int);
int int_to_fp (int);

int fp_div (int, int);
int fp_mul (int, int);

int 
fp_to_int (int x)
{
	return x / F;
}
int
fp_to_int_round (int x)
{
	int a = (x>=0) ? x+(F/2) : x-(F/2);
	return a / F;
}
int
int_to_fp (int x)
{
	return x * F;
}

int
fp_div (int x, int y)
{
	return ((int64_t)x) * F / y;
}

int
fp_mul (int x, int y)
{
	return ((int64_t)x) * y / F;
}
/* --- project 1.3 end --- */
