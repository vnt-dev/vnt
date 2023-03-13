use console::style;

pub fn println_table(table: Vec<Vec<String>>) {
    if table.is_empty() {
        return;
    }
    let mut width_list = vec![0; table[0].len()];
    for in_list in table.iter() {
        for (index, item) in in_list.iter().enumerate() {
            let width = console::measure_text_width(item) + 6;
            if width_list[index] < width {
                width_list[index] = width;
            }
        }
    }
    let mut head = true;
    for in_list in table {
        for (index, item) in in_list.iter().enumerate() {
            if head {
                print!("{item:width$}", item = item, width = width_list[index]);
            } else {
                let str = format!("{item:width$}", item = item, width = width_list[index]);
                print!("{}", style(str).green());
            }
        }
        head = false;
        println!()
    }
}