package sync

import (
	"fmt"
	//"log"
	"sort"
	"strings"
	"time"

	"github.com/go-zookeeper/zk"
)

func amILeader(zkHosts []string, leaderPath string) (bool, error) {
	conn, _, err := zk.Connect(zkHosts, time.Second*5)
	if err != nil {
		return false, fmt.Errorf("error connecting to ZooKeeper: %v", err)
	}
	defer conn.Close()

	exists, _, err := conn.Exists(leaderPath)
	if err != nil {
		return false, fmt.Errorf("error checking if leader path exists: %v", err)
	}

	if !exists {
		path, err := conn.Create(leaderPath, []byte{}, 0, zk.WorldACL(zk.PermAll))
		if err != nil && err != zk.ErrNodeExists {
			return false, fmt.Errorf("error ensuring leader path %s: %v", path, err)
		}
	}

	myZNode, err := conn.Create(fmt.Sprintf("%s/node-", leaderPath), []byte{}, zk.FlagSequence|zk.FlagEphemeral, zk.WorldACL(zk.PermAll))
	if err != nil {
		return false, fmt.Errorf("error creating sequential znode: %v", err)
	}

	myZNodeName := myZNode[strings.LastIndex(myZNode, "/")+1:]

	children, _, err := conn.Children(leaderPath)
	if err != nil {
		return false, fmt.Errorf("error getting children of leader path: %v", err)
	}

	sort.Strings(children)

	if children[0] == myZNodeName {
		return true, nil
	}

	return false, nil
}