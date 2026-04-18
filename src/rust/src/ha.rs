//! High Availability — Leader election + log replication.
//!
//! Simplified Raft-style consensus for MGEP exchange clusters:
//! - Leader accepts orders, sequences them, replicates to followers
//! - Followers receive replicated log, apply deterministically
//! - On leader failure, followers elect a new leader
//!
//! This is NOT a full Raft implementation — it's the minimum
//! needed for a 3-node exchange cluster with automatic failover.
//!
//! Architecture:
//!   Node 1 (Leader)  ←→  Node 2 (Follower)
//!          ↕                    ↕
//!   Node 3 (Follower)
//!
//! Leader sequences all incoming orders into a log.
//! Followers replicate the log and apply it to their matching engine.
//! If the leader fails, the follower with the most complete log becomes leader.

use std::time::{Duration, Instant};

/// Node role in the cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

/// Node state for consensus.
pub struct Node {
    pub id: u32,
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<u32>,
    pub log_index: u64,        // last applied log entry
    pub commit_index: u64,     // last committed (majority-acked)
    pub leader_id: Option<u32>,

    // Timing
    pub election_timeout: Duration,
    pub last_heartbeat: Instant,

    // Cluster
    pub peers: Vec<u32>,       // other node IDs
    pub votes_received: u32,
}

/// Messages between nodes for consensus.
#[derive(Clone, Debug)]
pub enum ConsensusMessage {
    /// Leader → Follower: replicate log entries.
    AppendEntries {
        term: u64,
        leader_id: u32,
        prev_log_index: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    /// Follower → Leader: ack/nack append.
    AppendEntriesResponse {
        term: u64,
        success: bool,
        match_index: u64,
    },
    /// Candidate → All: request vote.
    RequestVote {
        term: u64,
        candidate_id: u32,
        last_log_index: u64,
    },
    /// All → Candidate: vote response.
    VoteResponse {
        term: u64,
        vote_granted: bool,
    },
}

/// A single log entry — contains one MGEP message.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub data: Vec<u8>, // raw MGEP message bytes
}

impl Node {
    pub fn new(id: u32, peers: Vec<u32>) -> Self {
        Self {
            id,
            role: Role::Follower,
            current_term: 0,
            voted_for: None,
            log_index: 0,
            commit_index: 0,
            leader_id: None,
            election_timeout: Duration::from_millis(150 + (id as u64 * 37) % 150), // 150-300ms, varied
            last_heartbeat: Instant::now(),
            peers,
            votes_received: 0,
        }
    }

    /// Check if election timeout has elapsed (should start election).
    pub fn should_start_election(&self) -> bool {
        self.role != Role::Leader && self.last_heartbeat.elapsed() > self.election_timeout
    }

    /// Start an election — become candidate, increment term, vote for self.
    pub fn start_election(&mut self) -> ConsensusMessage {
        self.role = Role::Candidate;
        self.current_term += 1;
        self.voted_for = Some(self.id);
        self.votes_received = 1; // vote for self
        self.last_heartbeat = Instant::now(); // reset timeout

        ConsensusMessage::RequestVote {
            term: self.current_term,
            candidate_id: self.id,
            last_log_index: self.log_index,
        }
    }

    /// Handle a vote response.
    pub fn handle_vote_response(&mut self, msg: &ConsensusMessage) {
        if let ConsensusMessage::VoteResponse { term, vote_granted } = msg {
            if *term != self.current_term || self.role != Role::Candidate {
                return;
            }
            if *vote_granted {
                self.votes_received += 1;
                let majority = (self.peers.len() as u32).div_ceil(2) + 1;
                if self.votes_received >= majority {
                    self.become_leader();
                }
            }
        }
    }

    /// Handle a vote request.
    pub fn handle_request_vote(&mut self, msg: &ConsensusMessage) -> ConsensusMessage {
        if let ConsensusMessage::RequestVote { term, candidate_id, last_log_index } = msg {
            if *term < self.current_term {
                return ConsensusMessage::VoteResponse {
                    term: self.current_term,
                    vote_granted: false,
                };
            }

            if *term > self.current_term {
                self.current_term = *term;
                self.role = Role::Follower;
                self.voted_for = None;
            }

            let can_vote = self.voted_for.is_none() || self.voted_for == Some(*candidate_id);
            let log_ok = *last_log_index >= self.log_index;

            if can_vote && log_ok {
                self.voted_for = Some(*candidate_id);
                self.last_heartbeat = Instant::now();
                ConsensusMessage::VoteResponse { term: self.current_term, vote_granted: true }
            } else {
                ConsensusMessage::VoteResponse { term: self.current_term, vote_granted: false }
            }
        } else {
            ConsensusMessage::VoteResponse { term: self.current_term, vote_granted: false }
        }
    }

    /// Handle AppendEntries from leader.
    pub fn handle_append_entries(&mut self, msg: &ConsensusMessage) -> ConsensusMessage {
        if let ConsensusMessage::AppendEntries { term, leader_id, prev_log_index: _, entries, leader_commit } = msg {
            if *term < self.current_term {
                return ConsensusMessage::AppendEntriesResponse {
                    term: self.current_term, success: false, match_index: self.log_index,
                };
            }

            // Accept leader
            self.current_term = *term;
            self.role = Role::Follower;
            self.leader_id = Some(*leader_id);
            self.last_heartbeat = Instant::now();

            // Apply entries
            for entry in entries {
                if entry.index > self.log_index {
                    self.log_index = entry.index;
                }
            }

            if *leader_commit > self.commit_index {
                self.commit_index = (*leader_commit).min(self.log_index);
            }

            ConsensusMessage::AppendEntriesResponse {
                term: self.current_term,
                success: true,
                match_index: self.log_index,
            }
        } else {
            ConsensusMessage::AppendEntriesResponse {
                term: self.current_term, success: false, match_index: self.log_index,
            }
        }
    }

    /// Leader: create AppendEntries for heartbeat or replication.
    pub fn build_append_entries(&self, entries: Vec<LogEntry>) -> ConsensusMessage {
        ConsensusMessage::AppendEntries {
            term: self.current_term,
            leader_id: self.id,
            prev_log_index: self.log_index,
            entries,
            leader_commit: self.commit_index,
        }
    }

    /// Leader: sequence a new message and create a log entry.
    pub fn sequence_message(&mut self, data: Vec<u8>) -> LogEntry {
        self.log_index += 1;
        LogEntry {
            term: self.current_term,
            index: self.log_index,
            data,
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.leader_id = Some(self.id);
    }

    /// Is this node the leader?
    pub fn is_leader(&self) -> bool { self.role == Role::Leader }

    /// Cluster size (including self).
    pub fn cluster_size(&self) -> usize { self.peers.len() + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_node_election() {
        let mut node1 = Node::new(1, vec![2, 3]);
        let mut node2 = Node::new(2, vec![1, 3]);
        let mut node3 = Node::new(3, vec![1, 2]);

        // Node 1 starts election
        let request = node1.start_election();
        assert_eq!(node1.role, Role::Candidate);
        assert_eq!(node1.current_term, 1);

        // Nodes 2 and 3 vote
        let vote2 = node2.handle_request_vote(&request);
        let _vote3 = node3.handle_request_vote(&request);

        if let ConsensusMessage::VoteResponse { vote_granted, .. } = &vote2 {
            assert!(vote_granted);
        }

        // Node 1 receives votes
        node1.handle_vote_response(&vote2);
        // After 2 votes (self + node2), majority in 3-node cluster = 2
        assert_eq!(node1.role, Role::Leader);
    }

    #[test]
    fn leader_heartbeat() {
        let mut leader = Node::new(1, vec![2, 3]);
        leader.role = Role::Leader;
        leader.current_term = 1;
        leader.leader_id = Some(1);

        let mut follower = Node::new(2, vec![1, 3]);

        let heartbeat = leader.build_append_entries(vec![]);
        let response = follower.handle_append_entries(&heartbeat);

        assert_eq!(follower.leader_id, Some(1));
        if let ConsensusMessage::AppendEntriesResponse { success, .. } = response {
            assert!(success);
        }
    }

    #[test]
    fn leader_replicates_message() {
        let mut leader = Node::new(1, vec![2, 3]);
        leader.role = Role::Leader;
        leader.current_term = 1;

        // Sequence an MGEP message
        let entry = leader.sequence_message(vec![0x4D, 0x47, 1, 2, 3]);
        assert_eq!(entry.index, 1);
        assert_eq!(leader.log_index, 1);

        // Replicate to follower
        let mut follower = Node::new(2, vec![1, 3]);
        let append = leader.build_append_entries(vec![entry.clone()]);
        let resp = follower.handle_append_entries(&append);

        assert_eq!(follower.log_index, 1);
        if let ConsensusMessage::AppendEntriesResponse { match_index, .. } = resp {
            assert_eq!(match_index, 1);
        }
    }

    #[test]
    fn stale_term_rejected() {
        let mut node = Node::new(1, vec![2, 3]);
        node.current_term = 5;

        let stale = ConsensusMessage::AppendEntries {
            term: 3, // stale
            leader_id: 2,
            prev_log_index: 0,
            entries: vec![],
            leader_commit: 0,
        };

        let resp = node.handle_append_entries(&stale);
        if let ConsensusMessage::AppendEntriesResponse { success, .. } = resp {
            assert!(!success);
        }
    }

    #[test]
    fn five_node_cluster() {
        let mut nodes: Vec<Node> = (1..=5)
            .map(|id| Node::new(id, (1..=5).filter(|&x| x != id).collect()))
            .collect();

        // Node 0 starts election
        let request = nodes[0].start_election();

        // Collect votes
        let mut votes = Vec::new();
        for node in &mut nodes[1..] {
            votes.push(node.handle_request_vote(&request));
        }

        for vote in &votes {
            nodes[0].handle_vote_response(vote);
        }

        // Should be leader with majority (3 out of 5)
        assert_eq!(nodes[0].role, Role::Leader);
    }
}
