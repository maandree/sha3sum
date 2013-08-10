# Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
# 
# [GNU All Permissive License]

C_OPTIMISE=-O6
JAVA_OPTIMISE=-O

LIB_EXT=so

JAVAC=javac
JAVADIRS=-s "java" -d "bin/java" -cp "java"
JAVAFLAGS=-Xlint $(JAVA_OPTIMISE)
JAVA_FLAGS=$(JAVADIRS) $(JAVAFLAGS)

# NB!  Do not forget to test against -O0, -O4 to -O6 is not safe
CFLAGS=-W{all,extra} -pedantic $(C_OPTIMISE)
CPPFLAGS=
LDFLAGS=
C_FLAGS=$(CFLAGS) $(CPPFLAGS) $(LDFLAGS)

JNI_C_INCLUDE=-I$${JAVA_HOME}/include
JNI_C_FLAGS=$(JNI_INCLUDE) -fPIC -shared
JNI_JAVADIRS=-s "java-c-jni" -d "bin/java-c-jni" -cp "java-c-jni"
JNI_JAVAFLAGS=-Xlint $(JAVA_OPTIMISE)
JNI_JAVA_FLAGS=$(JNI_JAVADIRS) $(JNI_JAVAFLAGS)

JAVA_CLASSES = $(shell find "java" | grep '\.java$$' | sed -e 's_^_bin/_g' -e 's_java$$_class_g')
C_OBJS = $(shell find "c" | grep '\.h$$' | sed -e 's_^_bin/_g' -e 's_h$$_o_g')
C_BINS = bin/c/sha3sum
JNI_CLASSES = $(shell find "java-c-jni" | grep '\.java$$' | sed -e 's_^_bin/_g' -e 's_java$$_class_g')



all: java c java-c-jni



java: $(JAVA_CLASSES)
bin/java/%.class: java/%.java
	mkdir -p "bin/java"
	$(JAVAC) $(JAVA_FLAGS) "java/$*.java"


c: $(C_OBJS) $(C_BINS)
bin/c/%.o: c/%.h c/%.c
	mkdir -p "bin/c"
	$(CC) $(C_FLAGS) -c "c/$*".{c,h}
	mv "$*.o" "bin/c/$*.o"
bin/c/%: c/%.c
	$(CC) $(C_FLAGS) -o "$@" "c/$*".c "bin/c/"*.o


java-c-jni: bin/java-c-jni/SHA3.$(LIB_EXT) $(JNI_CLASSES)
bin/java-c-jni/%.class: java-c-jni/%.java
	mkdir -p "bin/java-c-jni"
	$(JAVAC) $(JNI_JAVA_FLAGS) "java-c-jni/$*.java"
java-c-jni/%.h: bin/java-c-jni/%.class
	javah -classpath bin/java-c-jni -jni -d java-c-jni \
	    $$(echo "$<" | sed -e 's:^bin/java-c-jni/::' -e 's:.class$$::' | sed -e 's:/:.:g')
bin/java-c-jni/%.so: java-c-jni/%.h java-c-jni/%.c
	mkdir -p "bin/java-c-jni"
	gcc $(C_FLAGS) $(JNI_C_FLAGS) "java-c-jni/$*.c" -o "bin/java-c-jni/$*.$(LIB_EXT)"



.PHONY: clean
clean:
	-rm {*/,}*.{t2d,aux,cp,cps,fn,ky,log,pg,pgs,toc,tp,vr,vrs,op,ops} 2>/dev/null
	-rm {*/,}*.{bak,info,pdf,ps,dvi,gz,class,jar,pyc,o,so,out} 2>/dev/null
	-rm java-c-jni/*.h 2>/dev/null
	-rm -r bin 2>/dev/null

