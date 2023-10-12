from aux.MSIS_security import MSIS_summarize_attacks, MSISParameterSet
from aux.MLWE_security import MLWE_summarize_attacks, MLWEParameterSet
from math import sqrt, log, pi, floor, ceil
from scipy.special import betaincinv, gammaln
import sys

# This script is a modification of the one for Dilithium, available at
# https://github.com/pq-crystals/security-estimates
# Please run python3 HAETAE-estimates.py --help for a list of commands.

#Select which estimators should be ran
#The key recovery estimator is much slower than the others and should be toggled off when k,l and eta are unchanged
weak_uf = True
strong_uf = True
key_recovery = True
size = True
fast_LWE = False

if "--no-weak_uf" in sys.argv:
    weak_uf = False
if "--no-strong_uf" in sys.argv:
    strong_uf = False
if "--no-key_recovery" in sys.argv:
    key_recovery = False
if "--no-size" in sys.argv:
    size = False
if "--fast_LWE" in sys.argv or "-f" in sys.argv:
    fast_LWE = True
if len(sys.argv)<=1 or "--help" in sys.argv:
    print("Security Estimator for HAETAE signature.\nOPTIONS:\n--record_xxx: Adds the record parameter sets for xxx security (xxx can be 120, 180 or 260) to the list of parameters.\n--param=\"n=256 q=122889 k=2 l=2 eta=3 security=120 adapt=1\": adds the following parameter set to the list. Multiple parameter sets can be input this way. security must be 120, 180 or 260. If adapt is set to 1, k, l and eta may be increased until target security is reached.\n--no-weak_uf: skips the weak unforgeability hardness computation.\n--no-strong_uf: skips the strong unforgeability hardness computation.\n--no-key_recovery: skips the key recovery hardness computation.\n--no-size: skips the expected verification key and signature sizes computation.\n--fast_LWE or -f: skips the dual attack for LWE parameters. Makes the script a lot faster. Note that this may overestimate the LWE cost by a few bits.")
    exit()

###########################################################################
######################## PRELIMINARIES ####################################
###########################################################################


#This defines, for each security level, the necessary entropy in the hash function.
#I have yet to understand why it is this way.
entropy = { 120 : 192, 180 : 225, 260 : 257 }


class FSParameterSet(object):
    def __init__(self, q, n=256, k=1, l=1, sigma=0, eta=5, security=120, alpha = 256, d=0):
        """
        This class represents a parameter set for the signature.
        """
        #Ring dimension and modulus
        self.n   = n
        self.q   = q

        #LWE parameters
        self.l   = l
        self.eta = eta

        #SIS parameters
        self.k = k

        self.sigma = sigma

        self.delta = log(self.sigma,2)
        self.d = d
        self.alpha = alpha
        self.B = 1.01*sqrt((self.l+self.k)*self.n)*self.sigma + sqrt(self.k*self.n)*(self.alpha/4+1)
        self.gamma2 = 2*(self.q-1)/self.alpha

        # SIS ell_2 bound for unforgeability, using selftargetMSIS
        self.zeta = self.B
        # SIS ell_2 bound for strong unforgeability
        self.zeta_prime = 2*self.B
        if(self.zeta>self.q):
            print("Warning: B > q, which may lead to improved attacks")



# Schemes parameters
####################
# Lowest values for q -> 6657, 5633, 3585, 2561, 1537, 1025.
n= 256

params  = []

#Parse input parameters
for s in sys.argv:
    if s[:len("--param=")] == "--param=":
        args = s[len("--param="):].split(' ') #Remove the beginning and final "
        print("Currently parsing",args,"\n")
        values = {"q" : "6657", "n" : "256", "k" : "1", "l" : "1", "security" : "120", "eta" : "2"}
        for opt in args:
            values[opt.split("=")[0]] = opt.split("=")[1]
        params += [("Fiat-Shamir Signature "+str(s), FSParameterSet(int(values["q"]), int(values["n"]), k=int(values["k"]), l=int(values["l"]), eta=int(values["eta"]), security=int(values["security"])))]



#Hardcoded parameters.
q_val = [64513, 95233, 125441, 202753]
#Precomputed values for sigma, with key acceptance rates of 0.1, 0.25 and 0.5
#Inputs are k, l and d
sigma_dict  = {
(2,4,0): {0.1: 488.99, 0.25: 505.06, 0.5: 523.41},
(2,4,1): {0.1: 566.98, 0.25: 584.64, 0.5: 611.60},
(3,4,0): {0.1: 519.51, 0.25: 535.14, 0.5: 556.05},
(3,4,1): {0.1: 616.13, 0.25: 637.28, 0.5: 664.18},
(3,5,0): {0.1: 546.25, 0.25: 563.38, 0.5: 584.00},
(3,5,1): {0.1: 641.42, 0.25: 658.51, 0.5: 683.16},
(3,6,0): {0.1: 578.43, 0.25: 594.47, 0.5: 611.63},
(3,6,1): {0.1: 661.18, 0.25: 680.86, 0.5: 704.98},
(4,5,0): {0.1: 579.17, 0.25: 592.24, 0.5: 610.88},
(4,5,1): {0.1: 681.58, 0.25: 700.22, 0.5: 727.68},
(4,7,0): {0.1: 625.55, 0.25: 640.14, 0.5: 658.89},
(4,7,1): {0.1: 724.16, 0.25: 742.45, 0.5: 767.40}}
dict_512 = {
(1,1,0): {0.1: 804.94, 0.25: 840.82, 0.5: 894.77},
(1,1,1): {0.1: 889.63, 0.25: 934.05, 0.5: 994.24}}
dict_1024 = {0.1: 703.11, 0.25: 727.96, 0.5: 767.76}

if "--record_120" in sys.argv:
    #Old parameter
    #params += [("G+G Signature Medium", FSParameterSet(95233, n=256, k=2, l=4, eta=1, security = 120, sigma = sqrt(2)*234.7, alpha = 128))]
    params += [("G+G Signature Medium", FSParameterSet(64513, n=256, k=3, l=4, eta=1, security = 120, sigma = sigma_dict[3,4,1][0.5], alpha = 512, d=1))]
    #params += [("G+G Signature Medium", FSParameterSet(64513, n=256, k=3, l=4, eta=1, security = 120, sigma = sigma_dict[3,4,0][0.5], alpha = 512, d=0))]
if "--record_180" in sys.argv:
    #params += [("G+G Signature Recommended", FSParameterSet(50177, n, k=4, l=5, eta=1, security = 180, sigma = sigma_dict[3,6,0][0.5], alpha = 512, d = 0))]
    params += [("G+G Signature Recommended", FSParameterSet(50177, n, k=4, l=5, eta=1, security = 180, sigma = sigma_dict[4,5,1][0.5], alpha = 512, d = 1))]
    #params += [("G+G Signature Recommended", FSParameterSet(202753, n, k=3, l=6, eta=1, security = 180, sigma = sigma_dict[3,6,0][0.5], alpha = 512, d = 0))]
if "--record_260" in sys.argv:
    params += [("G+G Signature Very High", FSParameterSet(202753, n, k=4, l=7, eta=1, security=260, sigma = sigma_dict[4,7,0][0.25], alpha = 512, d=0))]
if "--record_512_ntru" in sys.argv:
    #params += [("G+G NTRU Signature Medium", FSParameterSet(32257, n=512, k=1, l=1, eta=5, security = 120, sigma = sqrt(2)*991, alpha = 256))]
    #params += [("G+G NTRU Signature Medium", FSParameterSet(40961, n=512, k=1, l=1, eta=2, security = 120, sigma = dict_512[1,1,0][0.1], alpha = 256))]
    params += [("G+G NTRU Signature Medium", FSParameterSet(32257, n=512, k=1, l=1, eta=2, security = 120, sigma = dict_512[1,1,0][0.1], alpha = 256))]
if "--record_1024_ntru" in sys.argv:
    params += [("G+G NTRU Signature Recommended", FSParameterSet(50177, n=1024, k=1, l=1, eta=1, security = 180, sigma = dict_1024[0.5], alpha = 1024))]
    #params += [("G+G NTRU Signature Recommended", FSParameterSet(45569, n=1024, k=1, l=1, eta=1, security = 180, sigma = sqrt(2)*368.23, alpha = 2048))]


#########################
# Conversion to MSIS/MLWE
#########################

def FS_to_MSIS(dps, strong_uf = False):
    if strong_uf:
        return MSISParameterSet(dps.n, dps.k + dps.l, dps.k, dps.zeta_prime, dps.q, norm="l2")
    return MSISParameterSet(dps.n, dps.k + dps.l, dps.k, dps.zeta, dps.q, norm="l2")


def FS_to_MLWE(dps):
    #Also valid for Ring case as solving the NTRU instance is solving hf+g=0, an LWE instance
    return MLWEParameterSet(dps.n, max(dps.l-1,1), dps.k, dps.eta, dps.q, distr="uniform")

text_SIS = ["BKZ block-size $b$ to break SIS","Best Known Classical bit-cost","Best Known Quantum bit-cost"]
text_LWE = ["BKZ block-size $b$ to break LWE","Best Known Classical bit-cost","Best Known Quantum bit-cost"]


##################
# Size Computation
##################

def FS_Signature_Size(dps):
    """
    Computes the expected size of a signature depending on the type of distribution used.
    """
    #Size of tilde{c} is n bits
    size_c = dps.n 
    # See p.17 of Dilithium-G
    size_c_h = size_c + 2.5*dps.n*dps.k
    return size_c_h+(2.25+dps.delta)*dps.n*dps.l

def FS_Entropy(dps):
    """
    Computes the optimal expected size of a signature by replacing the encoding of z by its entropy
    """
    #Size of tilde{c} is n bits
    size_c = dps.n 
    # See p.17 of BLISS-G
    size_c_h = size_c + (1.8257+dps.delta-log(dps.alpha,2))*dps.n*dps.k
    return size_c_h+(1.8257+dps.delta)*dps.n*dps.l

def FS_PK_Size(dps):
    """
    Computes the expected size of a verification key. This does not depend on the distribution used.
    """
    return (256 + dps.k*dps.n*(int(log(dps.q,2)+1-dps.d))) #The public vector is computed mod q


# rest of script is just formatting
#############################################
######################### ANALYSIS AND REPORT 
#############################################



table_weak_SIS   = [len(params)*[0] for i in range(4)]
table_strong_SIS = [len(params)*[0] for i in range(4)]
table_LWE        = [len(params)*[0] for i in range(4)]
table_size       = [0 for i in range(len(params))]
table_entropy    = [0 for i in range(len(params))]
table_pk         = [0 for i in range(len(params))]


#For each selected scheme, build the estimate cost of selected attacks
j = 0
for (scheme, param) in params:
    print("\n"+scheme)
    print(param.__dict__)
    print("")
    if weak_uf:
        print("=== WEAK UF")
        v = MSIS_summarize_attacks(FS_to_MSIS(param))
        for i in range(4):
            table_weak_SIS[i][j] = v[i]
    if strong_uf:
        print("=== STRONG UF")
        v = MSIS_summarize_attacks(FS_to_MSIS(param, strong_uf=True))
        for i in range(4):
            table_strong_SIS[i][j] = v[i]
    if key_recovery:
        print("=== SECRET KEY RECOVERY")
        v = MLWE_summarize_attacks(FS_to_MLWE(param),fast_LWE)
        for i in range(4):
            table_LWE[i][j] = v[i]
    if size:
        print("=== SIGNATURE SIZE")
        table_size[j] = FS_Signature_Size(param)
        print(table_size[j])
        table_entropy[j] = FS_Entropy(param)
        print(table_entropy[j])
        print("=== PK SIZE")
        table_pk[j] = FS_PK_Size(param)
        print(table_pk[j])
    j+=1


print("FS SIGNATURE TABLE")
print("========================")
print("\\hline")
print("$q$"+"".join([" & "+str(dps[1].q) for dps in params]))
print("\\\\")
print("S"+"".join([" & "+str(dps[1].sigma/(2*sqrt(log(dps[1].n-1+dps[1].n*2**65)/pi))) for dps in params]))
print("\\\\")
print("s"+"".join([" & "+str(2*sqrt(log(dps[1].n-1+dps[1].n*2**65))) for dps in params]))
print("\\\\")
print("$\sigma$"+"".join([" & "+str(dps[1].sigma) for dps in params]))
print("\\\\")
print("$B$"+"".join([" & "+str(dps[1].zeta) for dps in params]))
print("\\\\")
print("$(m,k-m)$"+"".join([" & ("+str(dps[1].k)+","+str(dps[1].l)+")" for dps in params]))
print("\\\\")
print("$\\eta$"+"".join([" & "+str(dps[1].eta) for dps in params]))
print("\\\\")
print("$\\alpha$"+"".join([" & "+str(dps[1].alpha) for dps in params]))
print("\\\\")
print("\\hline")
for j in range(3):
    print(text_SIS[j]+"".join([" & "+str(table_weak_SIS[j][i])+" ("+str(table_strong_SIS[j][i])+")" for i in range(len(params))]))
    print("\\\\")
print("\\hline")
for j in range(3):
    print(text_LWE[j]+"".join([" & "+str(table_LWE[j][i]) for i in range(len(params))]))
    print("\\\\")
print("\\hline")
#print("Expected signature size"+"".join([" & "+str(int(table_size[distribution][i]/8)) for i in range(len(all_params[distribution]))]))
#print("\\\\")
print("Signature size with rANS"+"".join([" & "+str(int(table_entropy[i]/8)) for i in range(len(params))]))
print("\\\\")
print("Expected public key size"+"".join([" & "+str(int(table_pk[i]/8)) for i in range(len(params))]))
print("\\\\")
print("Sum"+"".join([" & "+str(int((table_pk[i]+table_entropy[i])/8)) for i in range(len(params))]))
print("\\\\")
print("\\hline")
print("========================")


