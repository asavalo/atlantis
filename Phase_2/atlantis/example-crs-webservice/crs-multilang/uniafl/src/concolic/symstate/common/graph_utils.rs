use std::collections::{HashMap, HashSet};
use std::hash::Hash;

#[allow(unused)]
pub(crate) fn connected_components<T: Hash + Eq + PartialEq + Clone>(
    graph: &HashMap<T, HashSet<T>>,
) -> Vec<HashSet<T>> {
    let mut visited = HashSet::new();
    let mut components = Vec::new();

    for node in graph.keys() {
        if !visited.contains(node) {
            let mut component = HashSet::new();
            dfs(node, graph, &mut visited, &mut component);
            components.push(component);
        }
    }

    components
}

fn dfs<T: Hash + Eq + PartialEq + Clone>(
    node: &T,
    graph: &HashMap<T, HashSet<T>>,
    visited: &mut HashSet<T>,
    component: &mut HashSet<T>,
) {
    let mut stack = vec![node.clone()];

    while let Some(current) = stack.pop() {
        if visited.insert(current.clone()) {
            component.insert(current.clone());
            if let Some(neighbors) = graph.get(&current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
    }
}
