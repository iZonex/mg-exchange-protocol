use mgep::session::*;
use mgep::messages::*;
use mgep::frame::*;

fn main() {
    println!("NegotiateResponseCore:");
    println!("  SIZE constant: {}", NegotiateResponseCore::SIZE);
    println!("  Actual size: {}", std::mem::size_of::<NegotiateResponseCore>());
    
    println!("\nNegotiateCore:");
    println!("  SIZE constant: {}", NegotiateCore::SIZE);
    println!("  Actual size: {}", std::mem::size_of::<NegotiateCore>());
    
    println!("\nNewOrderSingleCore:");
    println!("  SIZE constant: {}", NewOrderSingleCore::SIZE);
    println!("  Actual size: {}", std::mem::size_of::<NewOrderSingleCore>());
    
    println!("\nExecutionReportCore:");
    println!("  SIZE constant: {}", ExecutionReportCore::SIZE);
    println!("  Actual size: {}", std::mem::size_of::<ExecutionReportCore>());
}
