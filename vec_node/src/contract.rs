// use crate::node::{self, NodeService};
// use tonic::{Request, Response, Status};
// use vec_proto::messages::executor_server::Executor;
// use vec_proto::messages::{Confirmed, Contract, Transaction, TransactionInput, TransactionOutput};

// #[tonic::async_trait]
// impl Executor for NodeService {
//     async fn execute_contract(
//         &self,
//         request: Request<Transaction>,
//     ) -> Result<Response<Confirmed>, Status> {
//         let transaction = request.into_inner();
//         let contract = transaction.msg_contract;

//         Ok(Response::new(Confirmed {}))
//     }
// }
