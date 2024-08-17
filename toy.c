#include <stdio.h>

int transform(int value){

    // Some bitwise operations
    value &= 0xFF; //=150
    value ^= 0x9C; //=10
    value = value << 1; //=20

    // loop
    for (int i = 0; i < 3; i++){
        value += 5;
    }

    // control flow
    if (value > 30 ){
        value -= 30;
    }
    else if (value > 0){
        return value;
    }
    else{
       value += 15;
    }

    return value;//=5
}


int main(int argc, char const *argv[]){
    
    int init_val = 150;
    int result = transform(init_val);

    if (result == 5) {
        printf("I'm evil !");
    } else {
        printf("I'm benign !");
    }
    
    return 0;
}

