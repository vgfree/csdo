#!/bin/bash

if [ $# -lt 1 ] || [ $# -gt 3 ]; then
        echo -e "USAGE:\n\tpkg.sh \$project [\$branch] [\$source]"
        echo -e "  \$source: 'local' to use local repo, 'remote' or omit for git clone"
        exit 1
fi

TGT_VERSION=1.0.0
TGT=$1
BRANCH=$2
SOURCE=${3:-local}
ORG=`pwd`
DIR=$ORG/rpmbuild/$TGT
SRC=/tmp/$TGT-${TGT_VERSION}
TAR=/tmp/${TGT}-${TGT_VERSION}.tar.gz

#1# 清理环境
rm -rf $DIR
rm -rf $SRC
rm -rf $TAR

#2# 获取代码
if [ "$SOURCE" = "remote" ]; then
    if [ ! -z "$BRANCH" ]; then
        git clone https://github.com/vgfree/${TGT}.git $SRC -b $BRANCH
    else
        git clone https://github.com/vgfree/${TGT}.git $SRC
    fi
else
    cp -r ${ORG} $SRC
    cd $SRC
    if [ ! -z "$BRANCH" ]; then
        git checkout $BRANCH
    fi
fi

#3# 获取版本
cd $SRC
PACKAGE_RELEASE=`git rev-list --count HEAD`
PACKAGE_REVERSION=`git rev-parse --short HEAD`
echo ${TGT_VERSION} > /tmp/$TGT-${TGT_VERSION}/VERSION

git submodule init
git submodule update
git submodule foreach git submodule init
git submodule foreach git submodule update

cd $ORG

#4# 代码打包
tar -czvf $TAR -C /tmp/$TGT-${TGT_VERSION} . --exclude=./.*

#5# 准备资源
mkdir -p $DIR/{RPMS,SRPMS,BUILD,SOURCES,SPECS}
mv $TAR $DIR/SOURCES/
cp -rf source/* $DIR/SOURCES/
cp ${TGT}.spec $DIR/SPECS/

#6# 开始打包
home="_topdir $DIR"

eval QA_RPATHS=$[ 0x0002|0x0010 ] rpmbuild --nodebuginfo --define \"$home\" --define \"_version ${TGT_VERSION}\" --define \"_release ${PACKAGE_RELEASE}\" --define \"_reversion ${PACKAGE_REVERSION}\" -vv -ba $DIR/SPECS/${TGT}.spec
