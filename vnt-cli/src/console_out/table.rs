use console::Style;

pub fn println_table(table: Vec<Vec<(String, Style)>>) {
    if table.is_empty() {
        return;
    }
    let mut width_list = vec![0; table[0].len()];
    for in_list in table.iter() {
        for (index, (item, _)) in in_list.iter().enumerate() {
            let width = console::measure_text_width(item) + 4;
            if width_list[index] < width {
                width_list[index] = width;
            }
        }
    }
    for in_list in table {
        for (col, (item, style)) in in_list.iter().enumerate() {
            let str = format!("{:1$}", item, width_list[col]);
            print!("{}", style.apply_to(str));
        }
        println!()
    }
}