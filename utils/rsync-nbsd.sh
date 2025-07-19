TDNS_SRC=/Users/johani/src/git/tdns
TDNS_NBSD_DIR=root@172.16.1.37:/tmp/

if [ -n "$$TDNS_NBSD_DIR" ]; then
    echo rsyncing to ${TDNS_NBSD_DIR}
    (cd ${TDNS_SRC} ; rsync --delete --exclude=.git --exclude-from=${TDNS_SRC}/.gitignore -avx ${TDNS_SRC} ${TDNS_NBSD_DIR}/ )
else
    echo TDNS_NBSD_DIR is unset, rsync not possible
fi
