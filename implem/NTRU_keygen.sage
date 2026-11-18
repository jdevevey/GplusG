from sage.all import *
load("NTT.sage")
load("FFT.sage")

lvl = 0


n = [512,1024]
eta = [5,2]
q = [114689, 86017]
S = [346.95, 228.14]

#Necessary for invNTT
inv = [pow(n[i], -1, q[i]) for i in range(len(n))]


#def to_rot(s):
#    # Formula used: for a polynomial f, rot(f)_{i,j} = (-1)**floor((j-i)/n) * f_{j-i mod n}
#    S = [[(-1)**((j-(i%n[lvl]))//n[lvl]) * s[i//n[lvl]][(j-(i%n[lvl])) % n[lvl]] for j in range(n[lvl])] for i in range(n[lvl]*len(s))]
#    return Matrix(S)

def rejection_check(s):
    #rot_s = to_rot(s)
    #_, SV, _ = rot_s.change_ring(RDF).SVD()
    #sigma_1 = max([SV[i,i] for i in range(n[lvl])])
    sigma_1_squared = largest_sv(s, n[lvl])
    print("sigma_1^2 =",sigma_1_squared)
    return sigma_1_squared < S[lvl]**2

def keygen():
    zeta_poly = R([1]+[0]*(n[lvl]//2-1)+[1]+[0]*(n[lvl]//2-1))
    cont = True
    while(cont):
	#Generating secret
        print("new try")

        #Sample an invertible zeta*f+1, ie an f with 0 in NTT form
        f = Rq([ZZ.random_element(-eta[lvl], eta[lvl]+1) for i in range(n[lvl])])
        hat_f = NTT(Rq(1)+Rq(zeta_poly.lift())*f, T_zeta_list_NTRU[lvl])
        while(not(all(hat_f))):
            f = Rq([ZZ.random_element(-eta[lvl], eta[lvl]+1) for i in range(n[lvl])])
            hat_f = NTT(Rq(1)+Rq(zeta_poly.lift())*f, T_zeta_list_NTRU[lvl])


        g = R([ZZ.random_element(-eta[lvl], eta[lvl]+1) for i in range(n[lvl])])
        s1 = zeta_poly+ 2*R(x**(n[lvl]//2))*R([l.lift_centered() for l in f])
        s2 = -zeta_poly*g
        s = vector([s1, s2])
        #Rejection step: is the largest singular value too large?
        if rejection_check(s):
            cont = False
       

    inv_f = invNTT([pow(i, -1, q[lvl]) for i in hat_f], T_zeta_list_NTRU[lvl], inv[lvl])
 
    h = Rq(g.lift())*inv_f


    # "Packing" things up
    s1 = zeta_poly*R2q(f.lift()) + R2q(1)
    s2 = R2q((-g).lift())
    s = vector([s1, s2])

    a1 = R2q([2*i.lift() for i in h]) + q[lvl]*zeta_star_poly
    a2 = R2q(2)
    A = Matrix([[a1, a2]])
    return (A, s)

for lvl in range(2):
    R.<x> = PolynomialRing(ZZ)
    R.<x> = R.quotient(x ** n[lvl] +1)

    Rq.<x> = PolynomialRing(Zmod(q[lvl]))
    Rq.<x> = Rq.quotient(x ** n[lvl] + 1)

    R2q.<x> = PolynomialRing(Zmod(2*q[lvl]))
    R2q.<x> = R2q.quotient(x ** n[lvl] + 1)

    (A, s) = keygen()

    zeta_star_poly = R2q([1]+[0]*(n[lvl]//2-1)+[-1]+[0]*(n[lvl]//2-1))

    #Checking As = q*zeta^* mod 2q
    assert((A*s)[0] == zeta_star_poly*q[lvl])
    print("signing key for NTRU G+G lvl ",lvl,": ", (A,s))
