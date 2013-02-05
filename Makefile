# Copyright © 2013  Mattias Andrée (maandree@member.fsf.org)
# 
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.
# 
# [GNU All Permissive License]

JAVAC=javac


JAVA_CLASSES = $(shell find "pure-java" | grep '\.java$$' | sed -e 's_^_bin/_g' -e 's_java$$_class_g')


all: pure-java


pure-java: $(JAVA_CLASSES)
bin/pure-java/%.class: pure-java/%.java
	mkdir -p "bin/pure-java"
	$(JAVAC) -s "pure-java" -d "bin/pure-java" -cp "pure-java" "pure-java/$*.java"




.PHONY: clean
clean:
	rm {*/,}*.{t2d,aux,cp,cps,fn,ky,log,pg,pgs,toc,tp,vr,vrs,op,ops} 2>/dev/null || exit 0
	rm {*/,}*.{bak,info,pdf,ps,dvi,gz,class,jar,pyc,o,so} 2>/dev/null || exit 0
	rm -r bin 2>/dev/null || exit 0

