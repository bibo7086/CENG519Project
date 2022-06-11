from eva import EvaProgram, Input, Output, evaluate, Expr, py_to_eva
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse

import timeit
import networkx as nx
import random as rand
import numpy as np
import math

# These global variables are simply used for viewing the results
viewResults = True
generatedTree =  {}
queryNodes = []

# Using networkx, generate a random graph, in this case a tree 
# n - number of nodes 
def generateGraph(n):
    global generatedTree
    G = nx.random_tree(n=n, create_using=nx.DiGraph)
    generatedTree = G
    
    return G

# Represent a two dimensional adjacency matrix as a vector
# If there is an edge between two vertices its weight is 1 otherwise it is 0
# Assuming n vertices (i,j)th element = (i*n + j)th element in the vector 
# GG       - networkx generated graph 
# vec_size - the size of the vector
def serializeGraphZeroOne(GG,vec_size):
    n = GG.number_of_nodes()
    graph = []
    for row in range(n):
        for column in range(n):
            if GG.has_edge(row, column) or row==column: # I assumed the vertices are connected to themselves
                weight = 1
            else:
                weight = 0 
            graph.append(weight)  

    # For added security pad the eva vector with zeros
    # Not used in this program
    for i in range(vec_size - n*n): 
        graph.append(0.0)

    return graph

# Display the generated graph
# graph - graph 
# n     - number of nodes
def printGraph(graph,n):
    for row in range(n):
        for column in range(n):
            print("{:.2f}".format(round(graph[row*n+column])), end = '\t')
        print() 


# Eva requires special input, this function prepares the input
# Eva will then encrypt them
def prepareInput(n, m):
    input = {}
    GG = generateGraph(n)
    graph = serializeGraphZeroOne(GG, m)  

    input['Graph'] = graph

    return input

# Trying to use Boolean matrix multiplication
# Converts all nonzeros elements to 1
def prepareInput2(GG, n):
    m = n*n
    input = {}
    graph = []

    graph = [round(x) for x in GG]
    graph = [1 if x > 0 else 0 for x in graph]

    input['Graph'] = graph

    return input

# Eva requires special input, this function prepares
# query input
# Eva will then encrypt them
def queryInput(GG, n):
    global queryNodes
    m = n*n
    input = {}
    graph = []

    graph = [round(x) for x in GG]
    graph = [1 if x > 0 else 0 for x in graph]

    query = rand.sample(range(0,n), 2)
    queryNodes = query
    uv = query[0]*n + query[1]
    vu = query[1]*n + query[0]
    queryVector = [1 if ((x == uv) or (x == vu)) else 0 for x in range(m)]
    
    input['Graph'] = graph
    input['Query'] = queryVector

    return input

# Returns a vector v in {0,1}^n such that
# v[i] = pred(i)
def vecFromPred(n, pred): 
    return [1 if pred(l) else 0 for l in range(n)]

# Shifts a given vector (ciphertext) left k times
# graph - encrypted graph represented as vector 
def rot(graph, k): 
    return graph << k 

# Performs homomorphic matrix mutliplication
# using the algorithm from https://eprint.iacr.org/2018/1041.pdf
# and implementation from https://github.com/mark-schultz/EVA-matrix-multiplication/blob/main/matrix-mul.py
# given two encrypted square matrices (already vectorized), which represent a graph
# graph1 - 
# graph2 - 
# n      - number of nodes 
def matrixMultiplication(graph1, graph2, n): 
    d = n
    N = n**2

    ctA = [0.0 for _ in range(n)]
    for k in range(-d-1, d): 
        if k >= 0: 
            uk = vecFromPred(N, lambda l: 0 <= l - d*k < (d-k))
        else: 
            uk = vecFromPred(N, lambda l: -k <= l - (d+k) * d < d)
     
        # The purpose of this loop is to overcome an error
        # with vectors of zeros. For details check (https://github.com/microsoft/SEAL/issues/137#issuecomment-596432963)
        for i in range(len(uk)): 
            if(uk[i] == 0): 
                uk[i] = 0.000001  

        ctA += rot(graph1, k) * uk 

        ctB = [0.0 for _ in range(n)]
        for k in range(d): 
            ctB += rot(graph2, d * k) * vecFromPred(N, lambda l: (l % d) == k)
       

        ctAB = ctA * ctB 
        for k in range(1, d): 
            vk = vecFromPred(N, lambda l: 0 <= l % d < (d-k))
            vk_minus_d = vecFromPred(N, lambda l: (d-k) <= (l % d) < d)

            ctAk = rot(ctA, k) * vk + rot(ctA, k-d) * vk_minus_d
            ctBk = rot(ctB, d * k)

            ctAB += ctAk * ctBk

    return ctAB

# Given an encrypted query consisting of (u, v) and
# the encrypted transitive closure of a tree(graph)
# Returns whether or not the two nodes are on the same path 
def samePathChecker(transitiveclosure, query): 

    x = py_to_eva(transitiveclosure)
    x = transitiveclosure*query
    i = 1
    while i < x.program.vec_size:
        y = x << i
        x = x + y
        i <<= 1

    return x

# To avoid cluttering the simulat function moved the analytics here
# Would be better to have it in a seperate file
def analytics(prog, inputs): 
    prog.set_output_ranges(30)
    prog.set_input_scales(30)

    config = {}
    config['warn_vec_size'] = 'false'
    config['lazy_relinearize'] = 'true'
    config['rescaler'] = 'always'
    config['balance_reductions'] = 'true'
    
    start = timeit.default_timer()
    compiler = CKKSCompiler(config=config)
    compiled_multfunc, params, signature = compiler.compile(prog)
    compiletime = (timeit.default_timer() - start) * 1000.0 #ms

    start = timeit.default_timer()
    public_ctx, secret_ctx = generate_keys(params)
    keygenerationtime = (timeit.default_timer() - start) * 1000.0 #ms

    start = timeit.default_timer()
    encInputs = public_ctx.encrypt(inputs, signature)
    encryptiontime = (timeit.default_timer() - start) * 1000.0 #ms

    start = timeit.default_timer()
    encOutputs = public_ctx.execute(compiled_multfunc, encInputs)
    executiontime = (timeit.default_timer() - start) * 1000.0 #ms

    start = timeit.default_timer()
    outputs = secret_ctx.decrypt(encOutputs, signature)
    decryptiontime = (timeit.default_timer() - start) * 1000.0 #ms

    start = timeit.default_timer()
    reference = evaluate(compiled_multfunc, inputs)
    referenceexecutiontime = (timeit.default_timer() - start) * 1000.0 #ms
            
    # Since CKKS does approximate computations,
    # this is an important measure that depicts the amount of error  
    mse = valuation_mse(outputs, reference)

    return outputs, compiletime, keygenerationtime, encryptiontime, executiontime, decryptiontime, referenceexecutiontime, mse

# Do not change this 
# the parameter n can be passed in the call from simulate function
class EvaProgramDriver(EvaProgram):
    def __init__(self, name, vec_size=4096, n=4):
        self.n = n
        super().__init__(name, vec_size)

    def __enter__(self):
        super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback):
        super().__exit__(exc_type, exc_value, traceback)

# Repeat the experiments and show averages with confidence intervals
# n: the number of nodes in your graph
def simulate(n):
    global veiwResults, queryNodes, generatedTree
    outputTracker = []
    m = n*n
    totalCompiletime = totalKeygenerationtime = totalEncryptiontime = totalExecutiontime = totalDecryptiontime = totalReferenceexecutiontime = totalMse = 0

    # Step 1 - Compute the Transitive closure by repeated squaring O(log(n))
    graphanaltic = EvaProgramDriver("MatrixMultiplcation", vec_size=m)
    end = math.ceil(math.log(n, 2))
    for i in range(end):
        if (i == 0): 
            inputs = prepareInput(n, m)
        else: 
            inputs = prepareInput2(outputtracker, n)

        with graphanaltic:
            graph1 = Input('Graph')
            graph2 = graph1
            reval = matrixMultiplication(graph1, graph2, n)
            Output('ReturnedValue', reval)

        prog = graphanaltic
    

        outputs, compiletime, keygenerationtime, encryptiontime, executiontime, decryptiontime, referenceexecutiontime, mse =  analytics(prog, inputs)
    
        totalCompiletime += compiletime
        totalKeygenerationtime += keygenerationtime
        totalEncryptiontime += encryptiontime
        totalExecutiontime += executiontime
        totalDecryptiontime += decryptiontime
        totalReferenceexecutiontime += referenceexecutiontime
        totalMse += mse    
        result = outputs["ReturnedValue"]
        result = [round(x) for x in result]
        result = [1 if x >  0 else 0 for x in result]
        outputtracker = result
        # print(compiletime, keygenerationtime, encryptiontime, executiontime, decryptiontime, referenceexecutiontime)



    # Step 2: Determien whether two nodes are on the same path 
    inputs = queryInput(outputtracker, n)
    graphanaltic = EvaProgramDriver("Determine if two nodes are on the same path", vec_size=m)
    with graphanaltic:
        graph = Input('Graph')
        query = Input('Query')
        result = samePathChecker(graph, query)
        Output('Result', result)

    prog = graphanaltic
    prog.set_output_ranges(30)
    prog.set_input_scales(30)
    
    output, compiletime, keygenerationtime, encryptiontime, executiontime, decryptiontime, referenceexecutiontime, mse =  analytics(prog, inputs)
    totalCompiletime += compiletime
    totalKeygenerationtime += keygenerationtime
    totalEncryptiontime += encryptiontime
    totalExecutiontime += executiontime
    totalDecryptiontime += decryptiontime
    totalReferenceexecutiontime += referenceexecutiontime
    totalMse += mse

    # Set ViewResult to false if you dont want to see the results 
    if viewResults: 
        print(nx.forest_str(generatedTree))
        print("The transitive closure of the above tree is ")
        printGraph(outputtracker, n)
        if round(output['Result'][0]) >= 1: 
            print(f"Node {queryNodes[0]} and {queryNodes[1]} lie on the same path ")
        else: 
            print(f"Node {queryNodes[0]} and {queryNodes[1]} are not on the same path ")

    return totalCompiletime, totalKeygenerationtime, totalEncryptiontime, totalExecutiontime, totalDecryptiontime, totalReferenceexecutiontime, totalMse 

if __name__ == "__main__":
    simcnt = 1 # The number of simulation runs for each graph size
    resultfile = open("results.csv", "w")  
    resultfile.write("NodeCount,SimCnt,CompileTime,KeyGenerationTime,EncryptionTime,ExecutionTime,DecryptionTime,ReferenceExecutionTime,Mse\n")
    resultfile.close()
    # for nc in [4, 8, 16, 32]: # Node counts for experimenting various graph sizes
    for nc in [8]: # Node counts for experimenting various graph sizes
        n = nc

        print(f"Starting simulation for {n} nodes")
        resultfile = open("results.csv", "a")

        for i in range(simcnt):
            # Call the simulator
            compiletime, keygenerationtime, encryptiontime, executiontime, decryptiontime, referenceexecutiontime, mse = simulate(n)
            res = str(n) + "," + str(i) + "," + "{:.5f}".format(compiletime) + "," + "{:.5f}".format(keygenerationtime) + "," +  "{:.5f}".format(encryptiontime) + "," +  "{:.5f}".format(executiontime) + "," +  "{:.5f}".format(decryptiontime) + "," +  "{:.5f}".format(referenceexecutiontime) + "," +  "{:.9f}".format(mse) + "\n"
            resultfile.write(res)

    resultfile.close()
    