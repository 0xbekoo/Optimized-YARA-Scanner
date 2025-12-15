## **Optimized YARA Scanner with C Language**

The developed YARA scanner has been optimized for high performance and stability using the low-level memory management and system calls offered by the C language. The optimizations performed are detailed below.

<br>

#### 1. Preventing Interruptions Caused by Rule Errors
<hr>

The project performs a robustness check by subjecting each .yar file to a temporary compilation process before compiling the main rule set. Only rule files proven to be error-free are included in the main rule set for final compilation, ensuring that faulty rules are skipped and scanning can be performed with a stable rule set. 

The CheckRuleValidity function within the code tests each .yar file on a temporary compiler before adding it to the main compiler.

<br>

#### 2. Multi-Thread Architecture
<hr>

The project adopts the Latency Hiding strategy under Multi-Thread to overcome the I/O bottleneck. This strategy creates a Producer-Consumer design pattern:

- Producer (Main Thread): Dominates disk I/O operations and is the class that pushes file paths into a secure queue in memory.
- Consumers (Worker Threads): A class that retrieves data from the queue and performs the CPU-bound YARA matching process.

The Multi-Thread method is designed to leverage the power of multi-core systems. The application's operating principle is based on files first being collected by the main thread and then distributed to multiple threads running in parallel.

<br>

#### **3. Multi-Thread Management with Mutex**
<hr>

The project uses a mutex mechanism to prevent data inconsistencies that may arise from multi-threaded access. A mutex is a synchronization method that ensures only one thread can access a data structure or code block at a time. Through this mechanism, when a file is added to the job queue or a task is retrieved from the front of the queue, these two operations cannot occur simultaneously.

The mutex applies not only to this but also to the structure where statistics are stored; when the number of scanned files or error logs are updated, each operation is performed safely by a single thread.

<br>

#### **4. Memory-Mapped I/O Optimization**
<hr>
Traditional file reading methods (read / fread) cause performance loss by first copying data to the kernel buffer and then to user memory (double-copy). In this project, the mmap system call, which operates close to the Zero-Copy principle, was used to prevent performance loss during the scanning of large files. After files are opened with open in the WorkerThread function, the file content is directly mapped to the virtual address using mmap().

<br><br>

#### **5 Memory Optimization with Madvise**
<hr>
The YARA scanning engine reads the file content linearly from start to finish. madvise optimization is applied to inform the operating system kernel of this access pattern.
<br><br>
With madvise, it tells the kernel, “I will read this memory area sequentially.” The kernel uses this hint to perform aggressive Read-Ahead; that is, the kernel prepares the data from the disk to RAM before the processor even reaches that page. This dramatically reduces disk I/O latency.

## **Compiling and Running the Project**

Compile the project with this:

```bash
gcc -O3 -march=native -flto scanner.c -o yara_scanner -lyara -lpthread
```

Then you can run the project.

The project takes two parameters from the user:

```bash
./yara_scanner <yara_dir> <sample_dirz>
```

Give the yara rule directory to the first parameter and the sample file to the second parameter.
