pragma circom 2.0.3;

include "bigint.circom";
include "bigint_func.circom";

// a[k] registers can overflow
//  assume actual value of a < 2^{n*(k+m)} 
// p[k] registers in [0, 2^n)
// out[2][k] solving
//      a = p * out[0] + out[1] with out[1] in [0,p) 
// out[0] has m registers in range [-2^n, 2^n)
// out[1] has k registers in range [0, 2^n)
function get_signed_Fp_carry_witness(n, k, m, a, p){
    var out[2][50];
    var a_short[51] = signed_long_to_short(n, k, a); 

    /* // commenting out to improve speed
    // let me make sure everything is in <= k+m registers
    for(var j=k+m; j<50; j++)
        assert( a_short[j] == 0 );
    */

    if(a_short[50] == 0){
        out = long_div2(n, k, m, a_short, p);    
    }else{
        var a_pos[50];
        for(var i=0; i<k+m; i++) 
            a_pos[i] = -a_short[i];

        var X[2][50] = long_div2(n, k, m, a_pos, p);
        // what if X[1] is 0? 
        var Y_is_zero = 1;
        for(var i=0; i<k; i++){
            if(X[1][i] != 0)
                Y_is_zero = 0;
        }
        if( Y_is_zero == 1 ){
            out[1] = X[1];
        }else{
            out[1] = long_sub(n, k, p, X[1]); 
            
            X[0][0]++;
            if(X[0][0] >= (1<<n)){
                for(var i=0; i<m-1; i++){
                    var carry = X[0][i] \ (1<<n); 
                    X[0][i+1] += carry;
                    X[0][i] -= carry * (1<<n);
                }
                assert( X[0][m-1] < (1<<n) ); 
            }
        }
        for(var i=0; i<m; i++)
            out[0][i] = -X[0][i]; 
    }

    return out;
}

// constrain in = p * X + Y 
// in[i] in (-2^overflow, 2^overflow) 
// assume registers of X have abs value < 2^{overflow - n - log(min(k,m)) - 1} 
// assume overflow - 1 >= n 
template CheckCarryModP(n, k, m, overflow, p){
    signal input in[k]; 
    signal input X[m];
    signal input Y[k];

    assert( overflow < 251 );
    assert( n <= overflow - 1);
    component pX;
    component carry_check;

    pX = BigMultShortLongUnequal(n, k, m, overflow); // p has k registers, X has m registers, so output really has k+m-1 registers 
    // overflow register in  (-2^{overflow-1} , 2^{overflow-1})
    for(var i=0; i<k; i++)
        pX.a[i] <== p[i];
    for(var i=0; i<m; i++)
        pX.b[i] <== X[i];

    // in - p*X - Y has registers in (-2^{overflow+1}, 2^{overflow+1})
    carry_check = CheckCarryToZero(n, overflow+1, k+m-1 ); 
    for(var i=0; i<k; i++){
        carry_check.in[i] <== in[i] - pX.out[i] - Y[i]; 
    }
    for(var i=k; i<k+m-1; i++)
        carry_check.in[i] <== -pX.out[i];
}

// solve for in = p * X + out
// assume in has registers in (-2^overflow, 2^overflow) 
// X has registers lying in [-2^n, 2^n) 
// X has at most Ceil( overflow / n ) registers 

// out has registers in [0, 2^n) but don't constrain out < p
template SignedFpCarryModP(n, k, overflow, p){
    signal input in[k]; 
    var m = (overflow + n - 1) \ n; 
    signal output X[m];
    signal output out[k];

    assert( overflow < 251 );

    var Xvar[2][50] = get_signed_Fp_carry_witness(n, k, m, in, p); 
    component X_range_checks[m];
    component range_checks[k]; 
    //component lt = BigLessThan(n, k); 

    for(var i=0; i<k; i++){
        out[i] <-- Xvar[1][i];
        range_checks[i] = Num2Bits(n); 
        range_checks[i].in <== out[i];
        //lt.a[i] <== out[i];
        //lt.b[i] <== p[i];
    }
    //lt.out === 1;
    
    for(var i=0; i<m; i++){
        X[i] <-- Xvar[0][i];
        X_range_checks[i] = Num2Bits(n+1);
        X_range_checks[i].in <== X[i] + (1<<n); // X[i] should be between [-2^n, 2^n)
    }
    
    component mod_check = CheckCarryModP(n, k, m, overflow, p);
    for(var i=0; i<k; i++){
        mod_check.in[i] <== in[i];
        mod_check.Y[i] <== out[i];
    }
    for(var i=0; i<m; i++){
        mod_check.X[i] <== X[i];
    }
}

// Constrain in = 0 mod p by solving for in = p * X
// assume in has registers in (-2^overflow, 2^overflow) 
// X has registers lying in [-2^n, 2^n) 
// X has at most Ceil( overflow / n ) registers 

// save range check on Y compared to SignedFpCarryModP
template SignedCheckCarryModToZero(n, k, overflow, p){
    signal input in[k]; 
    var m = (overflow + n - 1) \ n; 
    signal output X[m];

    assert( overflow < 251 );

    var Xvar[2][50] = get_signed_Fp_carry_witness(n, k, m, in, p); 
    component X_range_checks[m];

    for(var i=0; i<m; i++){
        X[i] <-- Xvar[0][i];
        X_range_checks[i] = Num2Bits(n+1);
        X_range_checks[i].in <== X[i] + (1<<n); // X[i] should be between [-2^n, 2^n)
    }
    
    component mod_check = CheckCarryModP(n, k, m, overflow, p);
    for(var i=0; i<k; i++){
        mod_check.in[i] <== in[i];
        mod_check.Y[i] <== 0;
    }
    for(var i=0; i<m; i++){
        mod_check.X[i] <== X[i];
    }
}

template FpIsEqual(n, k, p){
    signal input in[2][k];
    signal output out;

    // check in[i] < p
    component lt[2];
    for(var i = 0; i < 2; i++){
        lt[i] = BigLessThan(n, k);
        for(var idx=0; idx<k; idx++){
            lt[i].a[idx] <== in[i][idx];
            lt[i].b[idx] <== p[idx];
        }
        lt[i].out === 1;
    }

    component isEqual[k+1];
    var sum = 0;
    for(var i = 0; i < k; i++){
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== in[0][i];
        isEqual[i].in[1] <== in[1][i];
        sum = sum + isEqual[i].out;
    }

    isEqual[k] = IsEqual();
    isEqual[k].in[0] <== sum;
    isEqual[k].in[1] <== k;
    out <== isEqual[k].out;
}