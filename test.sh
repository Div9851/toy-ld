assert() {
    testdata="$1"
    expected="$2"

    gcc -c -o testdata/main.o "$testdata"
    ./toy-ld testdata/main.o testdata/strlen.o testdata/start.o testdata/print.o

    actual=$(eval "./a.out")

    if [ "$actual" = "$expected" ]; then
        echo "$testdata: OK"
    else
        echo "$testdata: '$expected' expected, but got '$actual'"
    fi
}

as -o testdata/strlen.o testdata/strlen.s
as -o testdata/start.o testdata/start.s
as -o testdata/print.o testdata/print.s

assert 'testdata/test1.c' 'Hello, World!'
