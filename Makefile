# Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
# 
# [GNU All Permissive License]

JAVAC=javac
JAVADIRS=-s "pure-java" -d "bin/pure-java" -cp "pure-java"
JAVAFLAGS=-Xlint
JAVA_FLAGS=$(JAVADIRS) $(JAVAFLAGS)

# NB!  Do not forget to test against -O0, -O4 to -O6 is not safe
CFLAGS=-W{all,extra} -pedantic -O6
CPPFLAGS=
LDFLAGS=
C_FLAGS=$(CFLAGS) $(CPPFLAGS) $(LDFLAGS)

JNI_INCLUDE=-I$${JAVA_HOME}/include
JNI_FLAGS=$(JNI_INCLUDE) -fPIC -shared


JAVA_CLASSES = $(shell find "pure-java" | grep '\.java$$' | sed -e 's_^_bin/_g' -e 's_java$$_class_g')
C_OBJS = $(shell find "c" | grep '\.h$$' | sed -e 's_^_bin/_g' -e 's_h$$_o_g')
C_BINS = bin/c/sha3sum

all: pure-java c java-c-jni


pure-java: $(JAVA_CLASSES)
bin/pure-java/%.class: pure-java/%.java
	mkdir -p "bin/pure-java"
	$(JAVAC) $(JAVA_FLAGS) "pure-java/$*.java"

c: $(C_OBJS) $(C_BINS)
bin/c/%.o: c/%.h c/%.c
	mkdir -p "bin/c"
	$(CC) $(C_FLAGS) -c "c/$*".{c,h}
	mv "$*.o" "c/$*.o"
bin/c/%: c/%.c
	mkdir -p "bin/c"
	$(CC) $(C_FLAGS) -o "$@" "c/$*".c "c/"*.o

java-c-jni: bin/java-c-jni/SHA3.so
bin/java-c-jni/%.so: java-c-jni/%.c
	mkdir -p "bin/java-c-jni"
	gcc $(C_FLAGS) $(JNI_FLAGS) "java-c-jni/$*.c" -o "bin/java-c-jni/$*.so"


.PHONY: clean
clean:
	rm {*/,}*.{t2d,aux,cp,cps,fn,ky,log,pg,pgs,toc,tp,vr,vrs,op,ops} 2>/dev/null || exit 0
	rm {*/,}*.{bak,info,pdf,ps,dvi,gz,class,jar,pyc,o,so,out} 2>/dev/null || exit 0
	rm -r bin 2>/dev/null || exit 0

