use vec_errors::errors::*;
use wasmtime::*;

pub fn call(address: &[u8], function_name: &str, args: Vec<Val>) -> Result<(), VMError> {
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());

    let db = sled::open("C:/Vector/contracts_db").map_err(|_| VMError::DBInitializationFailed)?;

    let module_binary = db
        .get(address)
        .map_err(|_| VMError::DBReadError)?
        .ok_or(VMError::ContractNotFound)?
        .to_vec();

    let module = Module::new(&engine, module_binary).map_err(|_| VMError::ModuleInitFailed)?;
    let instance =
        Instance::new(&mut store, &module, &[]).map_err(|_| VMError::InstanceCreationError)?;

    let func = instance
        .get_func(&mut store, function_name)
        .ok_or(VMError::FunctionNotFound)?;

    let mut results = vec![Val::I32(0)];
    func.call(&mut store, &args, &mut results)
        .map_err(|_| VMError::FunctionCallError)?;

    println!("Result: {:?}", results);

    Ok(())
}
