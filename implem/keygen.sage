from sage.all import *
load("FFT.sage")

lvl = 0


n = 256
q = [64513, 114689, 64513]
S = [72.98, 123.93, 110.1]
m = [2, 3, 4]
k = [2+4, 3+6, 4+7]
#eta is hardcoded in the code below
d = [1, 1, 0]

R.<x> = PolynomialRing(ZZ)
R.<x> = R.quotient(x ** n +1)

zeta = [R(1 + x**(n//2)), R(2), R(2)]

def decomp(b, d):
    if d==0:
        return (vector([R(0) for i in range(m[lvl])]), b)
    #b is represented with coefficients in [0, q-1]
    bp = vector(R([x.lift() for x in p]) for p in b)
    b1 = vector([R([x if x%2 == 0 else 4*round(x/4) for x in p]) for p in bp])
    b0 = bp-b1
    return (b0, b1)

def rejection_check(s):
    sigma_1_squared = largest_sv(zeta[lvl] * s, n)
    print("sigma_1^2 =", sigma_1_squared)
    return sigma_1_squared < S[lvl]**2

def keygen():
    cont = True
    while(cont):
	#Generating secret
        print("new try")
        #Generating public matrix
        a = vector([Rq([ZZ.random_element(q[lvl]) for i in range(n)]) for j in range(m[lvl])])
        A_zero = Matrix([[Rq([ZZ.random_element(q[lvl]) for i in range(n)]) for j in range(k[lvl]-m[lvl]-1)] for p in range(m[lvl])])
        s1 = vector([R([ZZ.random_element(-1, 2) for i in range(n)]) for j in range(k[lvl]-m[lvl]-1)])
        s2 = vector([R([ZZ.random_element(-1, 2) for i in range(n)]) for j in range(m[lvl])])

        #Computing associated public key and its truncation
        s1q = vector(Rq, [p.lift() for p in s1])
        s2q = vector(Rq, [p.lift() for p in s2])
        b = a + A_zero * s1q + s2q
        if d[lvl]==1:
            (b0, b1) = decomp(b, d[lvl])
            #Forming the final vector
            s = vector([R(1)]+ s1.list() + (s2 - b0).list())
        else:
            b1 = b
            s = vector([R(1)]+ s1.list() + s2.list())

        #Rejection step: is the largest singular value too large?
        if rejection_check(s):
            cont = False

    # "Packing" things up
    twice_A_zero_mod_2q = Matrix([[R2q([2*c.lift() for c in A_zero[i][j].list()]) for j in range(k[lvl]-m[lvl]-1)] for i in range(m[lvl])])
    if lvl==0:
        J = vector([R2q(1 - x**(n//2))] + [R2q(0) for i in range(m[lvl]-1)])
    else:
        J = vector([R2q(1)] + [R2q(0) for i in range(m[lvl]-1)])
    a_minus_b1 = a - vector(Rq, [p.lift() for p in b1])
    A = Matrix([ [R2q([2*c.lift() for c in a_minus_b1[i]]) + q[lvl]*J[i] ] + [twice_A_zero_mod_2q[i][j] for j in range(k[lvl]-m[lvl]-1)] + [R2q(2) if i==j else R2q(0) for j in range(m[lvl])] for i in range(m[lvl])])

    #A = concat(2*(a-b1) + q * j_vec, 2*A_zero, 2*Id) % 2*q
    return (A, vector(R2q, [p.lift() for p in s]))

for lvl in range(3):
    Rq.<x> = PolynomialRing(Zmod(q[lvl]))
    Rq.<x> = Rq.quotient(x ** n + 1)
    
    R2q.<x> = PolynomialRing(Zmod(2*q[lvl]))
    R2q.<x> = R2q.quotient(x ** n + 1)
    
    (A, s) = keygen()

    if lvl==0:
        J = vector([R2q(1 - x**(n//2))] + [R2q(0) for i in range(m[lvl]-1)])
    else:
        J = vector([R2q(1)] + [R2q(0) for i in range(m[lvl]-1)])

    assert(A*s == q[lvl]*J)
    print("signing key for G+G lvl ",lvl,": ", (A, s))
