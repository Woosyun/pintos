/* --- project 1.3 start --- */
#include <stdint.h>
#define F (1<<14)

int fp_to_int (int);
int int_to_fp (int);
int fp_div (int, int);
int fp_mul (int, int);

int cal_recent_cpu (int, int, int);
int cal_priority (int, int);
int cal_load_avg (int, int);

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

//calculation is always done with two fp type variables?
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

int
cal_load_avg (int load_avg, int ready_threads)
{
	int a = fp_div (int_to_fp (59), int_to_fp (60));
	int x = fp_mul (a, load_avg);
	int b = fp_div (int_to_fp (1), int_to_fp (60));
	int y = fp_mul (b, int_to_fp (ready_threads));
	
	return x + y;
}

int
cal_recent_cpu (int load_avg, int recent_cpu, int nice)//nice is integer
{
	int fp_nice = int_to_fp (nice);
	
	int a1 = 2 * load_avg;// 2*load_avg
	int a = fp_div (a1, a1 + int_to_fp (1));// (2*load_avg)/(2*load_avg+1)
	int x = fp_mul (a, recent_cpu);// (2*load_avg)/(2*load_avg+1)*recent_cpu

	return x + fp_nice;
}

int
cal_priority (int recent_cpu, int nice)
{
	int a = int_to_fp (63 - 2*nice);
	int b = fp_div (recent_cpu, int_to_fp (4));
	int fp_new_priority = a - b;

	return fp_to_int (fp_new_priority);
}

/* --- project 1.3 end --- */
