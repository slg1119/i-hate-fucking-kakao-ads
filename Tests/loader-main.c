#include <stdio.h>
extern int no_ad_kakao_probe(void);
int main(void) {
    int result = no_ad_kakao_probe();
    printf("Hardened ad-hoc loader probe: %d\n", result);
    return result == 42 ? 0 : 1;
}
